# Primer despliegue en Azure — plan de implementación

> **Para agentes:** SUB-SKILL REQUERIDA: superpowers:executing-plans (en esta sesión, con puntos de control). La Parte A se puede delegar por tarea; la Parte B **no**: cada `apply`, cada gate y cada paso con el PSK los ejecuta o autoriza el operador. Los pasos usan casillas (`- [ ]`).

**Objetivo:** llevar las 4 VMs de `terraform/lab` de cero a capturando, siguiendo `ansible/PIPELINE.md` (Etapas 0–9), con lo aprendido en el ensayo local del 2026-11-05.

**Arquitectura:** la parte que controlamos (roles de Ansible) ya está probada en local (`evidence/local-tests/2026-11-05-ansible-local/RESULTADOS.md`: 4 rehearse en verde, `changed=0` en la Etapa 9, prueba negativa en rojo). Este plan cubre la parte que no se pudo ensayar: Terraform real, NSG, `run-command`, túnel, UFW, el pull por `Allow-Out-Maintenance-Egress` y el ciclo `deallocate`/`start`. Se despliega **por etapas en tres días**, con un gate entre cada una, para que un fallo de entorno aparezca donde empieza.

**Stack:** Terraform (azurerm), Azure CLI (`az`, `az rest`), Ansible core 2.21.1 en `nix-shell`, strongSwan 5.9.5 (swanctl), Wazuh 4.14.10, Docker 29.8.2 / Compose 5.6.0.

## Restricciones globales

- Ningún `terraform apply` sin la frase textual del operador. Etapa 2: `AUTORIZO terraform apply de /tmp/tfplan` (`make stage1`). Ventanas de egreso: autorización escrita en el chat antes de cada `-var maintenance_egress=…`.
- El PSK nunca entra al repo, a `group_vars`, al inventario, a Terraform, a `argv` ni a un log (A3, E1-5). Igual para `authd.pass` y `wazuh-install-files.tar`.
- `wazuh_secrets_dir` y el `known_hosts` de Azure viven **fuera del repo** (`~/soc-tesis-secrets/`).
- `host_key_checking = True` siempre (E1-4).
- E1-3: ningún servicio del honeypot activo ni habilitado mientras el egreso esté abierto.
- E1-9: no iniciar un día de Azure después de las 20:30 (`make time-guard`); auto-shutdown a las 22:00.
- Cada día de Azure termina con `az vm deallocate` de las 4 VMs (orden inverso: honeyserver → logrelay → wazuh → strongswan).
- Commits sin línea de coautor.

## Qué cambia respecto a `PIPELINE.md` (y por qué)

| Cambio | Motivo |
|---|---|
| Etapa 4a obtiene la **clave pública** de host, no solo la huella | Un `known_hosts` necesita la clave; la huella sirve para comprobarla a ojo. |
| Etapa 4b se ensaya primero con un **PSK de ensayo** | P-A2 sigue POR VERIFICAR: cómo recibe el script el parámetro protegido y si la instance view lo expone. Se comprueba sin arriesgar el secreto real. |
| Antes de Ansible se comprueba que las VMs ven el **origen 192.168.1.x** | UFW de `logrelay` y `wazuh` (nunca ejecutado en local) solo permite SSH desde `192.168.1.0/24`. Si la Pi hace NAT, Ansible se queda fuera al activar UFW. |
| La Etapa 6 va **por grupos** (`--limit`) con `ansible all -m ping` entre cada uno | Las tareas `solo host real` (UFW, sysctl, `vm.max_map_count`, NTP) corren por primera vez en Azure. |
| El cierre de egreso (Etapa 7) se ejercita **el Día 1**, antes de que exista el honeypot | Valida el NSG y E1-6 sin riesgo; el Día 2 se repite ya con el honeypot instalado. |
| En Azure, con el egreso cerrado, `curl` da **timeout**, no error de DNS | `Allow-Out-DNS` (prio 100) sigue permitido; en local la red `internal` no tenía DNS (`curl: (6)`). Los checks aceptan cualquier fallo. |
| Se instala también **`charon-systemd`** (rol `strongswan` y bootstrap) | Hallado al ejecutar la Tarea A2: `strongswan-swanctl` solo trae la CLI, y el daemon IKE y `strongswan.service` vienen en `charon-systemd`. En Azure, la Etapa 8 (`Asegurar strongSwan activo`) habría fallado y el túnel no habría levantado. En local no se veía porque esa tarea se salta en contenedor. |
| El ciclo `deallocate`/`start` es una **prueba explícita** (Día 3) | Es el mayor riesgo del diseño y en local solo se aproxima. |

---

# Parte A — Preparación local (sin costo)

### Tarea A1: known_hosts por `run-command` (Etapa 4a)

**Archivos:**
- Crear: `ansible/azure/host-keys.sh`

**Interfaces:**
- Produce: `bash ansible/azure/host-keys.sh <ruta known_hosts>` escribe 4 líneas (`10.50.20.10`, `10.50.40.10`, `10.50.30.10`, `[10.50.10.10]:22222`) e imprime la huella SHA256 de cada VM. `--selftest` prueba el parser sin Azure.
- Consume: `RG` (por defecto `rg-soc-tesis-lab`), sesión `az` vigente.

- [ ] **Paso 1: escribir el script**

```bash
#!/usr/bin/env bash
# Etapa 4a (E1-4): known_hosts de las 4 VMs leído por run-command (no depende
# de la red ni del túnel). Sin secretos: solo claves públicas de host.
set -euo pipefail

# Del mensaje de run-command, solo la clave ed25519 dentro de [stdout].
extract() { awk '/^\[stdout\]/{f=1;next} /^\[stderr\]/{f=0} f && $1=="ssh-ed25519"{print $1" "$2}'; }

if [ "${1:-}" = --selftest ]; then
  got=$(printf 'Enable succeeded: \n[stdout]\nssh-ed25519 AAAAC3x root@vm\n\n[stderr]\nssh-ed25519 MALA\n' | extract)
  [ "$got" = "ssh-ed25519 AAAAC3x" ] || { echo "host-keys selftest: FALLA ($got)" >&2; exit 1; }
  echo "host-keys selftest: ok"; exit 0
fi

OUT=${1:?uso: host-keys.sh <known_hosts fuera del repo> | --selftest}
RG=${RG:-rg-soc-tesis-lab}
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
case "$(realpath -m "$OUT")" in "$repo"/*) echo "host-keys: $OUT está dentro del repo" >&2; exit 1;; esac

declare -A HOSTS=(
  [vm-strongswan]=10.50.20.10
  [vm-wazuh]=10.50.40.10
  [vm-logrelay]=10.50.30.10
  [vm-honeyserver]='[10.50.10.10]:22222'
)
umask 077
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
for vm in vm-strongswan vm-wazuh vm-logrelay vm-honeyserver; do
  key=$(az vm run-command invoke -g "$RG" -n "$vm" --command-id RunShellScript \
        --scripts 'cat /etc/ssh/ssh_host_ed25519_key.pub' \
        --query 'value[0].message' -o tsv | extract)
  [ "$(printf '%s\n' "$key" | grep -c .)" = 1 ] || { echo "host-keys: $vm no devolvió una única clave ed25519" >&2; exit 1; }
  printf '%s %s\n' "${HOSTS[$vm]}" "$key" >>"$tmp"
  printf '%-15s %s\n' "$vm" "$(printf '%s %s\n' "${HOSTS[$vm]}" "$key" | ssh-keygen -lf - | awk '{print $2}')"
done
mv "$tmp" "$OUT"; trap - EXIT
echo "host-keys: 4 claves en $OUT"
```

- [ ] **Paso 2: verificar**

Run: `bash -n ansible/azure/host-keys.sh && bash ansible/azure/host-keys.sh --selftest && bash ansible/azure/host-keys.sh ./kh-prueba`
Expected: `host-keys selftest: ok` y, en la tercera, `host-keys: ./kh-prueba está dentro del repo` con exit 1.

- [ ] **Paso 3: commit** — `git add ansible/azure/host-keys.sh && git commit -m "feat(azure): known_hosts de las 4 VMs por run-command (Etapa 4a)"`

### Tarea A2: bootstrap de strongSwan y entrega del PSK (Etapa 4b)

**Decisión del operador (2026-11-05, APROBADA):** P3 (identidades IKE) y P4 (selectores) de ADR-004 §12, como constantes al inicio del script:
- `LOCAL_ID=azure-vpn.soc-tesis`, `PEER_ID=pi.soc-tesis`: identidades FQDN, porque la VM ve su IP privada (10.50.20.10) y la Pi ve la pública, así que las identidades por IP no coinciden con NAT de por medio.
- `LOCAL_TS=10.50.0.0/16`, `REMOTE_TS=192.168.1.0/24`, `remote_addrs=%any` (WAN del lab dinámica), propuestas `aes256gcm16-prfsha384-ecp384` / ESP `aes256gcm16-ecp384`, `dpd_action=clear` (la Pi reintenta con `restart`).

La Pi debe usar las mismas identidades, invertidas.

**Archivos:**
- Crear: `ansible/azure/bootstrap-strongswan.sh` (se ejecuta **en la VM**)
- Crear: `ansible/azure/psk-deliver.sh` (se ejecuta en el equipo del operador)

**Interfaces:**
- `bootstrap-strongswan.sh` recibe el PSK en la variable de entorno `PSK`. Es idempotente e imprime `swanctl --list-conns` y `psk-sha256: <12 hex>`.
- `psk-deliver.sh <archivo PSK 0600>`: crea el managed run command con `az rest` (el body es un JSON 0600 que se borra con `trap`, así el PSK nunca pasa por `argv`), espera a que termine, comprueba que el PSK no aparece en la instance view, imprime la salida y borra el run command.

- [ ] **Paso 1: script remoto**

```bash
#!/bin/bash
# Bootstrap de la VM strongSwan respondedora (ADR-006 E1-1/E1-5).
# Lo ejecuta managed run command con el parámetro protegido PSK.
# Sin set -x: este script maneja el secreto. printf es builtin (no aparece en argv).
set -eu
: "${PSK:?falta el parámetro protegido PSK}"
LOCAL_ID=azure-vpn.soc-tesis   # P3
PEER_ID=pi.soc-tesis           # P3
LOCAL_TS=10.50.0.0/16          # P4
REMOTE_TS=192.168.1.0/24       # P4

export DEBIAN_FRONTEND=noninteractive
# charon-systemd es el daemon IKE (strongswan.service); swanctl solo es la CLI.
if [ "$(dpkg-query -W -f='${db:Status-Abbrev}\n' strongswan-swanctl charon-systemd 2>/dev/null | grep -c '^ii')" != 2 ]; then
  apt-get update -q
  apt-get install -y -q strongswan-swanctl charon-systemd
fi

# Mismo contenido que escribe el rol strongswan: su primera pasada no cambia nada.
printf '%s\n' '# ADR-006 E1-1: la VM strongSwan reenvía solo lo que entra por el túnel.' \
  'net.ipv4.ip_forward = 1' >/etc/sysctl.d/99-soc-strongswan.conf
sysctl -p /etc/sysctl.d/99-soc-strongswan.conf

install -m 0644 -o root -g root /dev/null /etc/swanctl/conf.d/10-lab.conf
cat >/etc/swanctl/conf.d/10-lab.conf <<EOF
connections {
  lab {
    version = 2
    local_addrs = 10.50.20.10
    remote_addrs = %any
    proposals = aes256gcm16-prfsha384-ecp384
    dpd_delay = 30s
    local { auth = psk
            id = $LOCAL_ID }
    remote { auth = psk
             id = $PEER_ID }
    children {
      lab {
        local_ts = $LOCAL_TS
        remote_ts = $REMOTE_TS
        esp_proposals = aes256gcm16-ecp384
        dpd_action = clear
      }
    }
  }
}
EOF

install -m 0600 -o root -g root /dev/null /etc/swanctl/conf.d/90-lab-secret.conf
printf 'secrets {\n  ike-lab {\n    id = %s\n    secret = 0x%s\n  }\n}\n' "$PEER_ID" "$PSK" \
  >/etc/swanctl/conf.d/90-lab-secret.conf

systemctl enable --now strongswan
swanctl --load-all >/dev/null
swanctl --list-conns
printf 'psk-sha256: %s\n' "$(printf '%s' "$PSK" | sha256sum | cut -c1-12)"
```

- [ ] **Paso 2: probarlo en el contenedor `strongswan` del ensayo** (PSK de ensayo, nunca el real)

```bash
cd ansible && nix-shell --run 'make up'
docker cp azure/bootstrap-strongswan.sh soc-local-strongswan:/root/b.sh
DUMMY=$(openssl rand -hex 32)
docker exec -e PSK="$DUMMY" soc-local-strongswan bash /root/b.sh
docker exec -e PSK="$DUMMY" soc-local-strongswan bash /root/b.sh          # 2ª vez: idempotente
docker exec soc-local-strongswan stat -c '%a %U' /etc/swanctl/conf.d/90-lab-secret.conf
printf '%s' "$DUMMY" | sha256sum | cut -c1-12
```
Expected: las dos corridas listan la conexión `lab` (`IKEv2, no reauthentication`, `local: azure-vpn.soc-tesis`, children `10.50.0.0/16 === 192.168.1.0/24`). `stat` da `600 root`. El `psk-sha256` coincide con el último comando. Después: `make clean`.

- [ ] **Paso 3: script local de entrega**

```bash
#!/usr/bin/env bash
# Etapa 4b (E1-5): entrega el PSK a vm-strongswan con managed run command.
# El PSK solo viaja en un body JSON 0600 (borrado con trap) como parámetro
# protegido; nunca en argv. Al terminar se borra el run command.
set -euo pipefail
PSK_FILE=${1:?uso: psk-deliver.sh <archivo PSK 0600>}
RG=${RG:-rg-soc-tesis-lab}; VM=vm-strongswan; NAME=soc-bootstrap-strongswan
DIR=$(cd "$(dirname "$0")" && pwd)

[ "$(stat -c %a "$PSK_FILE")" = 600 ] || { echo "psk-deliver: $PSK_FILE debe ser 0600" >&2; exit 1; }
[ "$(grep -cxE '[0-9a-f]{64}' "$PSK_FILE")" = 1 ] && [ "$(wc -l <"$PSK_FILE")" -le 1 ] ||
  { echo "psk-deliver: el archivo debe tener una sola línea de 64 hex (openssl rand -hex 32)" >&2; exit 1; }

umask 077
body=$(mktemp); view=$(mktemp); trap 'rm -f "$body" "$view"' EXIT
loc=$(az vm show -g "$RG" -n "$VM" --query location -o tsv)
python3 - "$PSK_FILE" "$DIR/bootstrap-strongswan.sh" "$body" "$loc" <<'EOF'
import json, sys
clave = open(sys.argv[1]).read().strip()
script = open(sys.argv[2]).read()
json.dump({"location": sys.argv[4], "properties": {
    "source": {"script": script},
    "protectedParameters": [{"name": "PSK", "value": clave}],
    "asyncExecution": False, "timeoutInSeconds": 600}}, open(sys.argv[3], "w"))
EOF

api=$(az provider show -n Microsoft.Compute \
  --query "resourceTypes[?resourceType=='virtualMachines/runCommands'].apiVersions[0]" -o tsv)
sub=$(az account show --query id -o tsv)
az rest --method put -o none --body @"$body" \
  --url "https://management.azure.com/subscriptions/$sub/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VM/runCommands/$NAME?api-version=$api"
rm -f "$body"

st=
for _ in $(seq 60); do
  st=$(az vm run-command show -g "$RG" --vm-name "$VM" -n "$NAME" --instance-view \
       --query 'instanceView.executionState' -o tsv 2>/dev/null || true)
  case "$st" in Succeeded|Failed|TimedOut|Canceled) break;; esac
  sleep 10
done

az vm run-command show -g "$RG" --vm-name "$VM" -n "$NAME" --instance-view -o json >"$view"
leak=0; grep -qFf "$PSK_FILE" "$view" && leak=1
az vm run-command show -g "$RG" --vm-name "$VM" -n "$NAME" --instance-view \
  --query 'instanceView.{estado:executionState,exit:exitCode,salida:output,error:error}' -o yamlc
az vm run-command delete -g "$RG" --vm-name "$VM" -n "$NAME" --yes
echo "psk-local:  $(tr -d '\n' <"$PSK_FILE" | sha256sum | cut -c1-12)"

[ "$leak" = 0 ] || { echo "psk-deliver: EL PSK APARECE EN LA INSTANCE VIEW; rotarlo" >&2; exit 1; }
[ "$st" = Succeeded ] || { echo "psk-deliver: run command en estado '$st'" >&2; exit 1; }
echo "psk-deliver: ok"
```

- [ ] **Paso 4: verificar** — `for f in ansible/azure/*.sh; do bash -n "$f" || exit 1; done && nix-shell -p shellcheck --run "shellcheck ansible/azure/*.sh" && nix-shell --run 'make -C ansible secret-scan'`
Expected: sin errores; `secret-scan` sin hallazgos.

- [ ] **Paso 5: commit** — `git add ansible/azure/ && git commit -m "feat(azure): bootstrap de strongSwan y entrega del PSK por managed run command (Etapa 4b)"`

### Tarea A3: pre-vuelo del mismo día (repetir justo antes del Día 1 y del Día 2)

- [ ] `cd ansible && nix-shell --run 'make clean preflight && make wazuh-rehearse && make honeypot-rehearse && make stage9-rehearse'` → rc=0 en los cuatro (~21 min).
- [ ] `nix-shell --run 'make pin-check'` → sin pines retirados. **El instalador `/4.14/` de Wazuh es flotante:** si el gate de versión cambió (como pasó con 4.14.10), se para aquí, se sube el baseline y se repite el ensayo. No se descubre en Azure con el egreso abierto.
- [ ] `nix-shell --run 'make plan-check-selftest tags-contract'` → ok.
- [ ] `az vm list-usage -l centralus --query "[?name.value=='standardBasv2Family']"` → `limit` ≥ 10 (las 4 VMs usan las 10 vCPU; ADR-003).
- [ ] Secretos listos, **fuera del repo**: `~/soc-tesis-secrets/wazuh/authd.pass` (0600), PSK en la Pi (`openssl rand -hex 32`, 0600 root) y una copia 0600 en el equipo del operador para `psk-deliver.sh`; llave SSH del operador en `ANSIBLE_PRIVATE_KEY_FILE`.
- [ ] Pi: borrador `10-azure-lab.conf` completo con P3/P4/P8 (fuera de `/etc/swanctl/conf.d/` hasta la Etapa 5). Sin NAT/masquerade hacia `10.50.0.0/16`.

---

# Parte B — Despliegue (Azure, con costo)

Comandos desde `ansible/` dentro de `nix-shell`, salvo los de la Pi. Variables de sesión:
```bash
export EXPECTED_AZ_SUBSCRIPTION_NAME='…'
export ANSIBLE_PRIVATE_KEY_FILE=~/.ssh/<llave del lab>
export ANSIBLE_SSH_ARGS="-C -o ControlMaster=auto -o ControlPersist=60s -o IdentitiesOnly=yes -o UserKnownHostsFile=$HOME/soc-tesis-secrets/azure_known_hosts"
EV=evidence/azure/$(date +%F); mkdir -p "../$EV"      # salidas sin secretos
```

## Día 1 — Infraestructura, bootstrap, túnel y roles base (~3 h; empezar antes de las 17:00)

**Etapas 1–2 · Plan, apply y validación**
- [ ] `make stage1` → checks a–f en verde y la frase del gate. **Gate:** `AUTORIZO terraform apply de /tmp/tfplan`.
- [ ] `(cd ../terraform/lab && sha256sum -c /tmp/tfplan.authorized && terraform apply /tmp/tfplan) && rm -f /tmp/tfplan /tmp/tfplan.authorized`
- [ ] `terraform -chdir=../terraform/lab output` → `strongswan_public_ip`, `honeyserver_public_ip`, `private_ips`, `vm_ids`.
- [ ] `az vm list -d -g rg-soc-tesis-lab --query "[].{n:name,s:powerState}" -o table` → 4 `VM running`.
- [ ] `az resource list -g rg-soc-tesis-lab --resource-type Microsoft.DevTestLab/schedules --query "length(@)"` → `4`.
- [ ] **E1-2:** `timeout 8 nc -w5 <honeyserver_public_ip> 22 </dev/null | head -c 64` → **ningún** `SSH-2.0-OpenSSH`. Si aparece uno: `az vm deallocate -g rg-soc-tesis-lab -n vm-honeyserver` y se aborta (cloud-init no aplicó el `custom_data`).
- [ ] `terraform -chdir=../terraform/lab plan -var maintenance_egress=false -detailed-exitcode` → exit 0 ("No changes").

**Etapa 3 · Abrir egreso** — **Gate:** autorización escrita del operador.
- [ ] `terraform -chdir=../terraform/lab plan -var maintenance_egress=true -out=/tmp/tfplan-egress`; el plan solo agrega 4 × `Allow-Out-Maintenance-Egress`. Luego `apply /tmp/tfplan-egress && rm /tmp/tfplan-egress`.

**Etapa 4 · Bootstrap por run-command**
- [ ] 4a: `bash azure/host-keys.sh ~/soc-tesis-secrets/azure_known_hosts` → 4 huellas. Anotarlas en la evidencia.
- [ ] 4b, ensayo: `umask 077; openssl rand -hex 32 > ~/soc-tesis-secrets/psk-ensayo; bash azure/psk-deliver.sh ~/soc-tesis-secrets/psk-ensayo` → `psk-deliver: ok`, la conexión `lab` listada, `psk-sha256` = `psk-local`. **Si falla porque `PSK` llega vacío**, el script remoto se detiene sin escribir el secreto: se ajusta la forma del parámetro (P-A2) y se repite. Nunca se prueba la corrección con el PSK real.
- [ ] 4b, real: `bash azure/psk-deliver.sh ~/soc-tesis-secrets/psk` → ok y hashes iguales. Después `shred -u ~/soc-tesis-secrets/psk-ensayo`.
- [ ] Higiene: `grep -rFf ~/soc-tesis-secrets/psk ~/.zsh_history ~/.bash_history .. 2>/dev/null | wc -l` → `0`. `az vm run-command list -g rg-soc-tesis-lab --vm-name vm-strongswan -o tsv | wc -l` → `0`.

**Etapa 5 · Túnel** — **Gate:** sin túnel no se sigue.
- [ ] En la Pi: copiar el borrador a `/etc/swanctl/conf.d/`, `swanctl --load-all`, `swanctl --initiate --child lab`. Fuera del repo (A2, `handoff_opencode_red_vpn.md` Etapa D).
- [ ] `swanctl --list-sas` (Pi) → `ESTABLISHED` + `INSTALLED`. `ping -c3 10.50.20.10` desde la Pi y desde 192.168.1.73.
- [ ] `ansible all -m ping` → 4 `pong` (honeyserver por el 22222) con `StrictHostKeyChecking` activo.
- [ ] **Origen sin NAT:** `ansible logrelay,wazuh -m shell -a 'echo $SSH_CLIENT'` → empieza por `192.168.1.`. Si no, **parar**: UFW cortaría el SSH (corregir NAT en la Pi o `logrelay_admin_cidr`/su equivalente de wazuh antes de la Etapa 6).

**Etapa 6a · Roles base**
- [ ] `ansible-playbook site.yml --tags install,config --limit strongswan,logrelay | tee ../$EV/6a-pass1.log` → `failed=0 unreachable=0`.
- [ ] Inmediatamente: `ansible all -m ping`. Si falla solo `logrelay`: `az vm run-command invoke -g rg-soc-tesis-lab -n vm-logrelay --command-id RunShellScript --scripts "ufw disable"`, corregir el rol y repetir.
- [ ] `ansible strongswan -b -m command -a 'sysctl -n net.ipv4.ip_forward'` → `1`. `swanctl --list-sas` sigue con la SA (el rol no tocó el secreto).
- [ ] 2ª pasada `--limit strongswan,logrelay` → `changed=0`.
- [ ] `ansible all -b -m command -a 'timedatectl show -p NTPSynchronized --value'` → `yes` en las 4 **con el egreso todavía abierto**. Si sale `no`, revisar chrony/PTP de Hyper-V hoy, no el Día 2.

**Etapa 7 (ensayo temprano) · Cerrar egreso** — **Gate:** autorización escrita.
- [ ] `terraform -chdir=../terraform/lab apply -var maintenance_egress=false` (el plan solo quita las 4 reglas).
- [ ] `ansible all -m command -a 'curl -m5 -sS -o /dev/null http://1.1.1.1'` y `… https://example.com` → **fallan en las 4** (timeout; el DNS sí resuelve).
- [ ] `ansible all -m ping` → 4 `pong` (el túnel sigue).
- [ ] Cierre del día: `az vm deallocate` en orden inverso; `swanctl --terminate --ike lab` en la Pi.

## Día 2 — Wazuh, honeypot, cierre y arranque (~3 h)

- [ ] Repetir la Tarea A3 (`pin-check` como mínimo). `make time-guard`.
- [ ] `az vm start` en orden: strongswan → wazuh → logrelay → honeyserver. En la Pi: `swanctl --list-sas`; si no hay SA, `--initiate`. `ansible all -m ping` → 4 `pong`. **Primera observación del ciclo:** anotar cuánto tardó la SA y si hizo falta intervenir.
- [ ] **Abrir egreso** (Etapa 3, gate escrito).

**Etapa 6b · Wazuh** (descarga >1 GB, 10–25 min)
- [ ] `ansible-playbook site.yml --tags install,config --limit wazuh | tee ../$EV/6b-pass1.log` → `failed=0`. Si falla el gate de versión: no se instala nada más; decidir el baseline (Tarea A3) y repetir otro día.
- [ ] `ansible all -m ping` → 4 `pong` (UFW de wazuh activo). Rescate igual que en 6a, con `-n vm-wazuh`.

**Etapa 6c · Honeypot**
- [ ] `ansible-playbook site.yml --tags install,config --limit honeyserver | tee ../$EV/6c-pass1.log` → `failed=0`. Es el pull real de las 7 imágenes por el NSG.
- [ ] **E1-3** (lo mismo que el check 3 del ensayo):
  `ansible honeyserver -b -m shell -a 'for u in docker.service docker.socket containerd.service wazuh-agent.service; do echo "$u $(systemctl is-active $u) $(systemctl is-enabled $u)"; done; test ! -e /etc/soc-tesis/honeypot-started && test -s /etc/soc-tesis/honeypot-images && echo centinelas-ok'`
  → las 4 unidades `inactive disabled`, y `centinelas-ok`.

**Etapa 6d · Idempotencia completa**
- [ ] `ansible-playbook site.yml --tags install,config | tee ../$EV/6d-pass2.log` → `changed=0` en las 4.

**Etapa 7 · Cierre de egreso** — **Gate duro**: sin esto no hay Etapa 8.
- [ ] Sin descargas en curso (`ansible all -b -m shell -a 'pgrep -a "apt|dpkg|docker-pull|curl" || true'` vacío).
- [ ] `apply -var maintenance_egress=false` y las mismas tres verificaciones del Día 1.

**Etapa 8 · Arranque**
- [ ] `ansible-playbook site.yml --tags start | tee ../$EV/8-start1.log` → `failed=0`. El rol del honeypot se niega a arrancar si el egreso sigue abierto.
- [ ] 2ª `--tags start` → `changed=0`.
- [ ] Verificaciones de la tabla de la Etapa 8 de `PIPELINE.md`: SA; `wazuh-control info` = 4.14.10; `agent_control -l` con `honeyserver` `Active`; `stream.log` con `10.50.10.10 … TCP 200`; 7 contenedores `healthy`; el 22 público responde el banner de Cowrie (`SSH-2.0-OpenSSH_9.2p1 Debian…`), no el del host (`…Ubuntu…`); NTP `yes`.
- [ ] Evento de prueba desde fuera de Azure: `ssh -p 22 root@<honeyserver_public_ip>` (contraseña cualquiera) → aparece en Wazuh con el agente `honeyserver`. Anotar el tiempo de llegada.
- [ ] Cierre del día: `deallocate` en orden inverso.

## Día 3 — Ciclo `deallocate`/`start` y aceptación (Etapa 9, ~1.5 h)

- [ ] `az vm start` en orden. **Sin tocar nada**, registrar: SA (¿se levantó sola?), `ansible all -m ping`, los 7 contenedores `healthy` (`restart: unless-stopped`), agente `connected`, NTP `yes`, egreso cerrado (`curl` falla). Tabla "qué sobrevive / qué no" en la evidencia.
- [ ] Pasada completa sin tags: `ansible-playbook site.yml | tee ../$EV/9-full.log` → `changed=0 failed=0` en las 4 (en local esto lo cubría `stage9-rehearse`).
- [ ] `ansible-playbook site.yml --check --diff` → sin cambios.
- [ ] `terraform -chdir=../terraform/lab plan -var maintenance_egress=false -detailed-exitcode` → 0.
- [ ] Evidencia en `evidence/azure/<fecha>/`: logs, huellas, versiones, tabla del ciclo, `SHA256SUMS`. Higiene: `grep -rFf ~/soc-tesis-secrets/psk ../$EV` y lo mismo con `authd.pass` → 0.
- [ ] Cost Management: comparar el gasto real con el ≈ USD 35/mes de ADR-006 §6.
- [ ] `deallocate` en orden inverso.

## Si algo falla

| Dónde | Señal | Acción |
|---|---|---|
| Etapa 2 | banner real en el 22 | `deallocate` de honeyserver; revisar cloud-init (`az vm boot-diagnostics get-boot-log`) |
| Etapa 4b | `PSK` vacío o fuga en la instance view | parar; con el PSK de ensayo, ajustar el script; si se filtró el real, rotarlo (P-A3) |
| Etapa 5 | sin SA | revisar identidades y propuestas en ambos extremos; `swanctl --log` en la VM vía `run-command invoke` |
| Etapa 6 | sin `ping` tras UFW | `run-command invoke … "ufw disable"`, corregir y repetir |
| Etapa 6b | gate de versión | no seguir; baseline + ensayo local |
| Etapa 7 | `curl` responde | no arrancar nada; revisar reglas efectivas (`az network nic list-effective-nsg`) |
| Cualquiera después de las 20:30 | `time-guard` | cerrar el egreso si está abierto y hacer `deallocate`; seguir otro día |

## Después del despliegue

- Registrar en `ansible/PIPELINE.md` lo aprendido (Etapas 4a/4b reales, origen sin NAT, ejecución por grupos) y marcar P-A2 como verificado en ADR-006.
- **Pendiente antes del primer mantenimiento:** reabrir el egreso con el honeypot ya arrancado viola E1-3, porque Docker y el agente quedan habilitados y vuelven solos tras un `start`. Hace falta un procedimiento para detener y deshabilitar el honeypot antes de abrir el egreso, ensayado en local. No lo necesita este primer despliegue.
- Cada fallo de entorno que se pueda reproducir en local se convierte en un check del arnés, como se hizo con la caché de apt.
