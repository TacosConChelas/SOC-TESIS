# Rol `wazuh` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reemplazar el rol marcador `wazuh` por la instalación y configuración reales del all-in-one (Manager + Indexer + Dashboard), con gate de versión, secretos fuera del repo y ensayo local con el all-in-one real (`make wazuh-rehearse`).

**Architecture:** El rol instala con el asistente oficial `wazuh-install.sh -a` (único tag que descarga), verifica la versión contra `wazuh_expected_version`, y en `config` entrega `authd.pass` desde el controlador, edita `ossec.conf`, API, heap y política ISM, y trae el tar de contraseñas al controlador antes de destruirlo. El ensayo local usa el all-in-one real en el contenedor `wazuh`, con un target aparte para no alargar el `preflight`.

**Tech Stack:** Ansible (ansible-core 2.21, `community.general`), Wazuh 4.14 (asistente all-in-one), Ubuntu 22.04 (contenedor systemd), bash, Python 3 (stdlib), GNU make, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-30-wazuh-role-design.md` (commit `e3d713b`).

## Global Constraints

- Rama `practica/ansible-local`. Todo comando se corre desde `/home/tacosconchelas/Projects/SOC-TESIS/ansible` dentro de `nix-shell --run '...'`.
- Contrato de tags (E1-8): `install` es el único que descarga; `config` no descarga; `start` nunca descarga. En los roles, **cada tarea lleva sus propios tags** (también las anidadas en `block`/`rescue`), porque `tags-contract.py` los exige tarea por tarea.
- E1-7: las tareas no aplicables en contenedor llevan `when: ansible_virtualization_type != 'docker'` (UFW, `sysctl -p`).
- Versión esperada de Wazuh: `wazuh_expected_version: "4.14.8"` en `roles/wazuh/defaults/main.yml` con ese formato exacto (lo leen `wazuh-check.sh`, `wazuh-agent-fixture.sh` y `pin-check.sh`). Instalador: `https://packages.wazuh.com/4.14/wazuh-install.sh`; el asistente no admite fijar versión.
- Datos de D5: heap del Indexer `8g` (en el inventario local `2g`); retención de `wazuh-alerts-*` a 30 días; `logall` y `logall_json` en `no`; Active Response y `vulnerability-detection` apagados; `use_password yes`; `use_source_ip no`; API (55000) y Indexer (9200) solo en loopback; 1514/1515 desde el relay `10.50.30.10` y `lab_cidr` `192.168.1.0/24`; 443 y SSH desde `lab_cidr`.
- Secretos: nunca en el repo. `wazuh_secrets_dir` (controlador, por defecto `~/soc-tesis-secrets/wazuh`) debe estar **fuera** del repo: el rol falla si no. Toda tarea que toque contraseñas lleva `no_log: true`. El `shred` del tar solo ocurre tras comparar `sha256` con la copia traída al controlador. En el ensayo local los secretos viven en `/tmp/soc-local-secrets/` (700, desechables).
- UFW: entrada denegada, salida permitida; reglas `allow` antes de activar; solo con `when: ansible_virtualization_type != 'docker'`.
- Variables con prefijo `wazuh_` (regla `var-naming[no-role-prefix]` de `ansible-lint`), incluidas las de `register`.
- Los cambios se limitan a `ansible/` y `docs/`. No tocar `terraform/` ni `.knowledge/`. No agregar dependencias nuevas.
- Gates por código de salida (nunca por texto en stdout). Mensajes en español.
- Commits en español, sin líneas de atribución.
- No debilitar ningún check ni regla de lint para lograr verde: si un check parece mal escrito o el instalador real se comporta distinto a lo supuesto en este plan, **detenerse y reportar con evidencia**.
- Una corrida con el all-in-one real (`make wazuh-rehearse`, o `make wazuh-apply` con `install`) descarga más de 1 GB y tarda de 10 a 25 minutos, y `make clean preflight` más de 10: correrlas **en segundo plano con la salida a un archivo** y esperar a que terminen. No lanzar dos a la vez.
- Antes de `make wazuh-rehearse` por primera vez: `make clean preflight` (contenedores convergidos y `relay-check` en verde), porque el check 9 usa el relay.

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `ansible/local/scripts/wazuh-hostcheck.sh` (nuevo) | Verifica RAM, disco y `vm.max_map_count` del anfitrión (solo lee) |
| `ansible/local/scripts/gen-wazuh-secrets.sh` (nuevo) | Crea `authd.pass` desechable en `/tmp/soc-local-secrets/` |
| `ansible/local/scripts/wazuh-conf-check.py` (nuevo) | Valida los valores de `ossec.conf` (check 4) |
| `ansible/local/scripts/wazuh-agent-fixture.sh` (nuevo) | Fixture del arnés: instala `wazuh-agent` en `honeyserver` y lo enrola por el relay |
| `ansible/local/scripts/wazuh-check.sh` (nuevo) | Los 10 checks del diseño §6 (subconjunto con `WAZUH_CHECKS`) |
| `ansible/local/scripts/pin-check.sh` (mod) | Verifica que el asistente instalaría `wazuh_expected_version` |
| `ansible/local/inventory.yml` (mod) | Variables locales del host `wazuh` |
| `ansible/Makefile` (mod) | Targets `wazuh-hostcheck`, `wazuh-secrets`, `wazuh-apply`, `wazuh-rehearse`, `wazuh-check`; `clean` borra los secretos |
| `ansible/roles/wazuh/defaults/main.yml` (nuevo) | Variables `wazuh_*` |
| `ansible/roles/wazuh/handlers/main.yml` (nuevo) | Reinicios de manager e indexer |
| `ansible/roles/wazuh/templates/ism-retention.json.j2` (nuevo) | Política ISM de retención |
| `ansible/roles/wazuh/files/local_rules.xml` (nuevo) | Punto de enganche de reglas locales |
| `ansible/roles/wazuh/tasks/main.yml` (reemplaza) | Tareas `install`, `config` y `start` |
| `ansible/PIPELINE.md`, `ansible/local/README.md`, spec (mod) | Documentación y refinamientos |

**Refinamiento de la spec (se registra en la Tarea 6):** si hay `/var/ossec` sin el centinela, el rol **no** se detiene de inmediato: reejecuta el gate de versión y comprueba que los cuatro paquetes estén instalados; si ambos pasan, escribe el centinela (reanudación, p. ej. tras subir `wazuh_expected_version`); si no, se detiene y pide desinstalar a mano. El instalador solo corre si no existe `/var/ossec/bin/wazuh-control`.

**Paralelismo:** la Tarea 5 (`pin-check`) es independiente de la Tarea 1 y puede ejecutarse a la vez. Las Tareas 2, 3 y 4 son secuenciales y la 6 va al final. Si `git` reporta `index.lock`, esperar unos segundos y reintentar.

---

### Task 1: Arnés y `wazuh-check` (primero la prueba, en rojo)

**Files:**
- Create: `ansible/local/scripts/wazuh-hostcheck.sh`, `gen-wazuh-secrets.sh`, `wazuh-conf-check.py`, `wazuh-agent-fixture.sh`, `wazuh-check.sh`
- Modify: `ansible/local/inventory.yml`, `ansible/Makefile`

**Interfaces:**
- Produces: `make wazuh-hostcheck`, `make wazuh-secrets`, `make wazuh-apply TAGS=...`, `make wazuh-rehearse`, `make wazuh-check` (acepta `WAZUH_CHECKS="1 2 ..."`). Los checks leen `wazuh_expected_version`, `wazuh_indexer_heap` y `wazuh_retention_days` de `ansible/roles/wazuh/defaults/main.yml` (que crea la Tarea 2) y el inventario local.

- [ ] **Step 1: Verificación del anfitrión**

Crear `ansible/local/scripts/wazuh-hostcheck.sh`:

```bash
#!/usr/bin/env bash
# Requisitos del anfitrion para el all-in-one real en el contenedor. Solo lee; no cambia nada.
set -euo pipefail

min_mem_mb="${WAZUH_MIN_MEM_MB:-6144}"
min_disk_gb="${WAZUH_MIN_DISK_GB:-15}"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }

avail_mb="$(awk '/^MemAvailable:/ {print int($2/1024)}' /proc/meminfo)"
if [ "$avail_mb" -ge "$min_mem_mb" ]; then
  good "memoria disponible ${avail_mb} MiB (minimo ${min_mem_mb})"
else
  bad "memoria disponible ${avail_mb} MiB; se necesitan ${min_mem_mb} MiB (cierra programas o baja WAZUH_MIN_MEM_MB bajo tu riesgo)"
fi

map_count="$(cat /proc/sys/vm/max_map_count)"
if [ "$map_count" -ge 262144 ]; then
  good "vm.max_map_count=${map_count} (minimo 262144)"
else
  bad "vm.max_map_count=${map_count}; el Indexer pide 262144. Ajustalo en el anfitrion (p. ej. sudo sysctl -w vm.max_map_count=262144); este script no lo cambia"
fi

root_dir="$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || true)"
if [ -n "$root_dir" ]; then
  free_gb="$(df --output=avail -BG "$root_dir" | tail -n 1 | tr -dc '0-9')"
  if [ "${free_gb:-0}" -ge "$min_disk_gb" ]; then
    good "disco libre en ${root_dir}: ${free_gb} GiB (minimo ${min_disk_gb})"
  else
    bad "disco libre en ${root_dir}: ${free_gb:-0} GiB; se necesitan ${min_disk_gb} GiB"
  fi
else
  bad "no se pudo consultar el demonio de Docker"
fi

if docker inspect -f '{{.State.Running}}' soc-local-wazuh 2>/dev/null | grep -qx true; then
  good "contenedor soc-local-wazuh en ejecucion"
else
  bad "soc-local-wazuh no esta en ejecucion (corre make up o make rehearse)"
fi

if [ "$fail" -ne 0 ]; then
  echo "wazuh-hostcheck: FALLA" >&2
  exit 1
fi
echo "wazuh-hostcheck: ok"
```

- [ ] **Step 2: Secretos desechables del ensayo**

Crear `ansible/local/scripts/gen-wazuh-secrets.sh`:

```bash
#!/usr/bin/env bash
# Secretos DESECHABLES del ensayo local, fuera del repo (la guarda del rol wazuh lo exige).
set -euo pipefail

dir="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
umask 077
mkdir -p "$dir"
chmod 700 "$dir"

if [ ! -s "$dir/authd.pass" ]; then
  openssl rand -base64 32 >"$dir/authd.pass"
fi
chmod 600 "$dir/authd.pass"
echo "wazuh-secrets: ok ($dir)"
```

- [ ] **Step 3: Validador de `ossec.conf`**

Crear `ansible/local/scripts/wazuh-conf-check.py`:

```python
#!/usr/bin/env python3
"""Comprueba en ossec.conf los valores de D5. Uso: wazuh-conf-check.py /ruta/ossec.conf

Entrada CONFIABLE: el ossec.conf propio del contenedor de ensayo (root, desechable). Por eso
basta xml.etree de la biblioteca estandar; si algun dia se usara con XML ajeno, cambiar a
defusedxml (XXE y billion-laughs).
"""
import sys
import xml.etree.ElementTree as ET

# ossec.conf tiene varios <ossec_config>: se envuelve en una raiz para parsearlo.
raw = open(sys.argv[1], encoding="utf-8").read()
root = ET.fromstring("<r>" + raw + "</r>")


def textos(ruta: str) -> list[str]:
    return [(e.text or "").strip() for e in root.findall(ruta)]


esperado = [
    ("global/logall", "no"),
    ("global/logall_json", "no"),
    ("auth/use_password", "yes"),
    ("auth/use_source_ip", "no"),
    ("vulnerability-detection/enabled", "no"),
    ("active-response/disabled", "yes"),
]

mal = 0
for ruta, quiero in esperado:
    hay = textos(f".//{ruta}")
    if hay and all(v == quiero for v in hay):
        print(f"ok {ruta}={quiero}")
    else:
        print(f"FALLA {ruta}: esperado {quiero}, hay {hay}")
        mal = 1
sys.exit(mal)
```

- [ ] **Step 4: Fixture del agente (solo arnés)**

Crear `ansible/local/scripts/wazuh-agent-fixture.sh`:

```bash
#!/usr/bin/env bash
# Fixture del ARNES (no del rol): instala wazuh-agent en honeyserver y lo enrola por el relay (D4).
# El rol `honeypot` hara esto de verdad mas adelante. Requiere el egreso abierto.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
defaults="$here/../../roles/wazuh/defaults/main.yml"
secrets="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
ctr=soc-local-honeyserver
relay_ctr=soc-local-logrelay
relay_ip=10.50.30.10

version="$(sed -n 's/^wazuh_expected_version:[[:space:]]*"\([^"]*\)".*/\1/p' "$defaults" | head -n1)"
[ -n "$version" ] || { echo "FALLA: wazuh_expected_version no esta definida en $defaults" >&2; exit 1; }
[ -s "$secrets/authd.pass" ] || { echo "FALLA: falta $secrets/authd.pass (make wazuh-secrets)" >&2; exit 1; }
docker exec "$relay_ctr" systemctl is-active --quiet nginx \
  || { echo "FALLA: nginx del relay no esta activo (corre make rehearse antes)" >&2; exit 1; }

if docker exec "$ctr" dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "wazuh-agent-fixture: wazuh-agent ya instalado en honeyserver"
else
  env_file="$(mktemp)"
  trap 'rm -f "$env_file"' EXIT
  chmod 600 "$env_file"
  printf 'WAZUH_MANAGER=%s\nWAZUH_REGISTRATION_PASSWORD=%s\n' "$relay_ip" "$(tr -d '\n' <"$secrets/authd.pass")" >"$env_file"

  docker exec "$ctr" sh -c '
    set -e
    apt-get update -qq
    apt-get install -y -qq gnupg >/dev/null
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      >/etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
  '
  docker exec --env-file "$env_file" "$ctr" sh -c "apt-get install -y -qq wazuh-agent=${version}-1"
fi

docker exec "$ctr" systemctl enable --now wazuh-agent
echo "wazuh-agent-fixture: ok (agente ${version} apuntando al relay ${relay_ip})"
```

- [ ] **Step 5: `wazuh-check.sh`**

Crear `ansible/local/scripts/wazuh-check.sh`:

```bash
#!/usr/bin/env bash
# Verifica el rol wazuh en el ensayo local (spec 2026-10-30-wazuh-role-design.md §6).
# Requiere el all-in-one instalado (make wazuh-rehearse). Subconjunto: WAZUH_CHECKS="1 2".
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ansible_dir="$(cd "$here/../.." && pwd)"
repo="$(cd "$ansible_dir/.." && pwd)"
defaults="$ansible_dir/roles/wazuh/defaults/main.yml"
secrets="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
ctr=soc-local-wazuh
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }
wz() { docker exec "$ctr" "$@"; }
default_of() {
  sed -n -e "s/^$1:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
         -e "s/^$1:[[:space:]]*\([0-9][0-9a-z]*\)[[:space:]]*\(#.*\)\{0,1\}$/\1/p" "$defaults" | head -n1
}
admin_pass() {
  tar -axf "$secrets/wazuh-install-files.tar" wazuh-install-files/wazuh-passwords.txt -O 2>/dev/null \
    | grep -P "\'admin\'" -A 1 | tail -n 1 | sed -E "s/.*'([^']*)'.*/\1/"
}

want_version="$(default_of wazuh_expected_version)"
[ -n "$want_version" ] || { echo "FALLA: wazuh_expected_version no esta en $defaults" >&2; exit 1; }

# 1. Version esperada y paquetes retenidos.
c1() {
  local info holds pkg
  info="$(wz /var/ossec/bin/wazuh-control info 2>/dev/null || true)"
  if grep -q "WAZUH_VERSION=\"v${want_version}\"" <<<"$info"; then good "wazuh-control info reporta v${want_version}"; else bad "wazuh-control info no reporta v${want_version}"; fi
  holds="$(wz apt-mark showhold 2>/dev/null || true)"
  for pkg in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
    if grep -qx "$pkg" <<<"$holds"; then good "$pkg retenido"; else bad "$pkg no esta retenido"; fi
  done
}

# 2. Servicios activos.
c2() {
  local svc
  for svc in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
    if wz systemctl is-active --quiet "$svc"; then good "$svc activo"; else bad "$svc no esta activo"; fi
  done
}

# 3. Puertos de D5.
c3() {
  local tcp p
  tcp="$(wz ss -ltnH 2>/dev/null | awk '{n=split($4,a,":"); port=a[n]; addr=substr($4,1,length($4)-length(port)-1); print addr, port}')"
  for p in 1514 1515 443; do
    if awk -v p="$p" '$2==p && $1!~/^(127\.|\[::1\])/ {f=1} END{exit !f}' <<<"$tcp"; then good "puerto $p escucha en interfaces no loopback"; else bad "puerto $p no escucha fuera de loopback"; fi
  done
  for p in 9200 55000; do
    if awk -v p="$p" '$2==p {seen=1; if ($1!~/^(127\.|\[::1\])/) mal=1} END{exit !(seen && !mal)}' <<<"$tcp"; then good "puerto $p solo en loopback"; else bad "puerto $p no esta solo en loopback"; fi
  done
  for p in 9300 1516 514; do
    if awk -v p="$p" '$2==p && $1!~/^(127\.|\[::1\])/ {f=1} END{exit f}' <<<"$tcp"; then good "puerto $p sin escucha fuera de loopback"; else bad "puerto $p escucha fuera de loopback"; fi
  done
  if wz ss -lunH 2>/dev/null | awk '$4 ~ /:1514$/ {f=1} END{exit f}'; then good "1514/udp cerrado"; else bad "1514/udp escucha"; fi
}

# 4. ossec.conf.
c4() {
  local out
  if out="$(docker exec -i "$ctr" python3 - /var/ossec/etc/ossec.conf <"$here/wazuh-conf-check.py" 2>&1)"; then
    good "ossec.conf con los valores de D5"; sed 's/^/    /' <<<"$out"
  else
    bad "ossec.conf no cumple D5"; sed 's/^/    /' <<<"$out" >&2
  fi
  if wz /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then good "wazuh-analysisd -t"; else bad "wazuh-analysisd -t falla"; fi
}

# 5. authd.pass.
c5() {
  local meta have want
  meta="$(wz stat -c '%a %U:%G' /var/ossec/etc/authd.pass 2>/dev/null || true)"
  if [ "$meta" = "640 root:wazuh" ]; then good "authd.pass 640 root:wazuh"; else bad "authd.pass con permisos '$meta'"; fi
  have="$(wz sha256sum /var/ossec/etc/authd.pass 2>/dev/null | cut -d' ' -f1 || true)"
  want="$(sha256sum "$secrets/authd.pass" 2>/dev/null | cut -d' ' -f1 || true)"
  if [ -n "$have" ] && [ "$have" = "$want" ]; then good "authd.pass coincide con el del controlador"; else bad "authd.pass distinto del del controlador"; fi
}

# 6. Heap del Indexer.
c6() {
  local heap
  heap="$(cd "$ansible_dir" && ansible-inventory --host wazuh 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("wazuh_indexer_heap",""))' 2>/dev/null || true)"
  [ -n "$heap" ] || heap="$(default_of wazuh_indexer_heap)"
  if wz grep -qx "-Xms${heap}" /etc/wazuh-indexer/jvm.options && wz grep -qx "-Xmx${heap}" /etc/wazuh-indexer/jvm.options; then
    good "jvm.options con -Xms${heap} -Xmx${heap}"
  else
    bad "jvm.options sin -Xms${heap} / -Xmx${heap}"
  fi
}

# 7. Politica ISM de retencion.
c7() {
  local days pw resp
  days="$(default_of wazuh_retention_days)"
  pw="$(admin_pass || true)"
  if [ -z "$pw" ]; then bad "no se pudo leer la contrasena de admin de $secrets/wazuh-install-files.tar"; return; fi
  resp="$(printf 'user = "admin:%s"\n' "$pw" \
    | docker exec -i "$ctr" curl -sk -K - "https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-alert-retention-policy" || true)"
  if python3 - "$resp" "$days" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
pol = d["policy"]
pol = pol.get("policy", pol)
edades = [t["conditions"]["min_index_age"] for s in pol["states"] for t in s.get("transitions", []) if "conditions" in t]
pats = [p for t in (pol.get("ism_template") or []) for p in t.get("index_patterns", [])]
sys.exit(0 if f"{sys.argv[2]}d" in edades and "wazuh-alerts-*" in pats else 1)
PY
  then good "politica ISM borra wazuh-alerts-* a ${days}d"; else bad "la politica ISM no existe o no borra wazuh-alerts-* a ${days}d"; fi
}

# 8. Higiene de secretos.
c8() {
  if wz test ! -e /root/wazuh-install-files.tar; then good "el tar no queda en la VM"; else bad "el tar sigue en la VM"; fi
  if wz test ! -e /var/log/wazuh-install.log; then good "el log del asistente no queda en la VM"; else bad "el log del asistente sigue en la VM"; fi
  if [ "$(stat -c %a "$secrets/wazuh-install-files.tar" 2>/dev/null || true)" = 600 ]; then good "tar en el controlador con 0600"; else bad "falta el tar en $secrets o no es 0600"; fi
  if (cd "$repo" && python3 ansible/local/scripts/secret-scan.py >/dev/null 2>&1); then good "secret-scan limpio"; else bad "secret-scan encontro secretos"; fi
}

# 9. Cadena D4 real: agente en honeyserver enrolado por el relay.
c9() {
  local i
  for i in $(seq 1 12); do
    if wz /var/ossec/bin/agent_control -l 2>/dev/null | grep -Eq 'Name: honeyserver, IP: any, Active'; then
      good "agente honeyserver activo en el Manager (enrolado por el relay)"; return
    fi
    sleep 5
  done
  bad "el agente honeyserver no aparece activo en agent_control -l"
}

# 10. Prueba negativa del gate de version.
c10() {
  local out
  if [ -z "${ANSIBLE_INVENTORY:-}" ]; then bad "ejecuta este check via make wazuh-check (faltan las variables ANSIBLE_*)"; return; fi
  out="$(cd "$ansible_dir" && ansible-playbook site.yml --limit wazuh --tags install \
    -e wazuh_enabled=true -e wazuh_expected_version=4.14.0 2>&1 || true)"
  if grep -q 'desviación del baseline D1' <<<"$out"; then good "el gate de version falla con una version distinta"; else bad "el gate de version no fallo con wazuh_expected_version=4.14.0"; fi
}

for n in ${WAZUH_CHECKS:-1 2 3 4 5 6 7 8 9 10}; do "c$n"; done

if [ "$fail" -ne 0 ]; then
  echo "wazuh-check: FALLA" >&2
  exit 1
fi
echo "wazuh-check: ok"
```

- [ ] **Step 6: Variables locales del host `wazuh`**

En `ansible/local/inventory.yml`, reemplazar la línea:

```yaml
        wazuh: { ansible_host: 10.50.40.10 }
```

por:

```yaml
        wazuh:
          ansible_host: 10.50.40.10
          wazuh_enabled: false # make wazuh-rehearse lo activa con -e; preflight no instala Wazuh
          wazuh_indexer_heap: "2g" # el real (8g) no cabe en el ensayo local
          wazuh_secrets_dir: /tmp/soc-local-secrets # fuera del repo (la guarda del rol lo exige)
```

- [ ] **Step 7: Targets del Makefile**

En `ansible/Makefile`:

1. En `.PHONY`, reemplazar la última línea (`        pin-check clean`) por:

```make
        pin-check wazuh-hostcheck wazuh-secrets wazuh-apply wazuh-rehearse wazuh-check clean
```

2. En `help`, después de la línea de `pin-check`, agregar:

```make
	@echo "  make wazuh-rehearse     all-in-one real de Wazuh en el contenedor (10-25 min; fuera de preflight)"
	@echo "  make wazuh-check        verifica el rol wazuh (requiere wazuh-rehearse; WAZUH_CHECKS=\"1 2\" para un subconjunto)"
	@echo "  make wazuh-apply TAGS=install   aplica el rol wazuh con esos tags (iteracion)"
```

3. Después del target `pin-check:` (su receta de una línea), agregar:

```make

wazuh-hostcheck:
	@bash "$(LOCAL)/scripts/wazuh-hostcheck.sh"

wazuh-secrets:
	@bash "$(LOCAL)/scripts/gen-wazuh-secrets.sh"

wazuh-check:
	@bash "$(LOCAL)/scripts/wazuh-check.sh"

# Iteracion: aplica el rol wazuh con los tags indicados (por defecto install,config).
wazuh-apply: wazuh-secrets known-hosts
	@bash "$(LOCAL)/scripts/net-toggle.sh" install
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit wazuh --tags "$(or $(TAGS),install,config)" -e wazuh_enabled=true

wazuh-rehearse: wazuh-hostcheck wazuh-secrets known-hosts
	@mkdir -p "$(LOGS)"
	@echo "== Wazuh: egreso abierto (instalacion del all-in-one) =="
	@bash "$(LOCAL)/scripts/net-toggle.sh" install
	@echo "== Wazuh 1a pasada (install,config): debe aplicar cambios; tarda 10-25 min =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit wazuh --tags install,config -e wazuh_enabled=true 2>&1 | tee "$(LOGS)/wazuh-pass1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/wazuh-pass1.log" changed
	@echo "== Wazuh 2a pasada: idempotente =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit wazuh --tags install,config -e wazuh_enabled=true 2>&1 | tee "$(LOGS)/wazuh-pass2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/wazuh-pass2.log" nochange
	@echo "== Wazuh --check --diff tras converger =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit wazuh --tags install,config -e wazuh_enabled=true --check --diff 2>&1 | tee "$(LOGS)/wazuh-check.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/wazuh-check.log" nochange
	@echo "== Fixture del arnes: agente en honeyserver enrolado por el relay (D4) =="
	@bash "$(LOCAL)/scripts/wazuh-agent-fixture.sh"
	@echo "== Wazuh: egreso cerrado y arranque en dos pasadas =="
	@bash "$(LOCAL)/scripts/net-toggle.sh" operate
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit wazuh --tags start -e wazuh_enabled=true 2>&1 | tee "$(LOGS)/wazuh-start1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/wazuh-start1.log" ok
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit wazuh --tags start -e wazuh_enabled=true 2>&1 | tee "$(LOGS)/wazuh-start2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/wazuh-start2.log" nochange
	@$(MAKE) --no-print-directory wazuh-check
	@echo "wazuh-rehearse: ok"
```

4. En la receta de `clean`, reemplazar la línea `	@rm -rf "$(LOGS)" ...` por la misma con `/tmp/soc-local-secrets` agregado al final:

```make
	@rm -rf "$(LOGS)" "$(LOCAL)/.known_hosts" "$(LOCAL)/.keys" "$(LOCAL)/.selftest-scan.txt" /tmp/soc-local-secrets
```

- [ ] **Step 8: Lint estático y cableado**

Run: `cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'shellcheck local/scripts/wazuh-hostcheck.sh local/scripts/gen-wazuh-secrets.sh local/scripts/wazuh-agent-fixture.sh local/scripts/wazuh-check.sh && python3 -I -m py_compile local/scripts/wazuh-conf-check.py && make -n wazuh-rehearse >/dev/null && echo ESTATICO-OK'`
Expected: `ESTATICO-OK`. Si `shellcheck` marca algo, corregir la causa en el script.

- [ ] **Step 9: Levantar el entorno sin Wazuh y comprobar el anfitrión**

Run (en segundo plano, salida a archivo): `nix-shell --run 'make clean preflight'`
Expected: `rc=0` y `preflight: Etapa 0 OK`. El rol `wazuh` sigue siendo el marcador, y como `wazuh_enabled: false` en el inventario local no cambia nada.
Luego: `nix-shell --run 'make wazuh-secrets wazuh-hostcheck'`
Expected: `wazuh-secrets: ok (/tmp/soc-local-secrets)` y `wazuh-hostcheck: ok`. Si el anfitrión no cumple (poca RAM libre), cerrar programas y repetir; no bajar los mínimos para forzar el verde.

- [ ] **Step 10: `wazuh-check` debe FALLAR (rojo)**

Run: `nix-shell --run 'WAZUH_CHECKS="1 2" make wazuh-check'; echo "rc=$?"`
Expected: líneas `FALLA` (no hay `/var/ossec/bin/wazuh-control`, servicios inexistentes) y `wazuh-check: FALLA`; **nunca** `wazuh-check: ok`. Nota: el check 1 necesita `wazuh_expected_version` en los defaults del rol, que aún no existen. Mientras no exista, el script debe terminar con exit ≠ 0 y el mensaje `wazuh_expected_version no esta en ...`: eso también es rojo válido; anotar cuál de los dos se vio.

- [ ] **Step 11: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/local/scripts/wazuh-hostcheck.sh ansible/local/scripts/gen-wazuh-secrets.sh ansible/local/scripts/wazuh-conf-check.py ansible/local/scripts/wazuh-agent-fixture.sh ansible/local/scripts/wazuh-check.sh ansible/local/inventory.yml ansible/Makefile
git commit -m "test(ansible): arnés y wazuh-check del all-in-one (en rojo)" -m "wazuh-rehearse, wazuh-apply y wazuh-check con 10 checks (version, servicios, puertos, ossec.conf, authd.pass, heap, ISM, higiene de secretos, cadena D4 real y gate negativo). El inventario local desactiva el rol para que preflight siga siendo rapido."
```

---

### Task 2: Rol `wazuh`, parte 1: instalación, gate de versión y retención de paquetes

**Files:**
- Create: `ansible/roles/wazuh/defaults/main.yml`
- Replace: `ansible/roles/wazuh/tasks/main.yml`

**Interfaces:**
- Consumes: Tarea 1 (`make wazuh-apply TAGS=install`, `WAZUH_CHECKS`).
- Produces: variables `wazuh_*`; centinela `/etc/soc-tesis/wazuh-installed`; `/root/wazuh-install-files.tar` (lo consume la Tarea 3).

- [ ] **Step 1: Variables**

Crear `ansible/roles/wazuh/defaults/main.yml`:

```yaml
---
# Rol wazuh. Diseño: docs/superpowers/specs/2026-10-30-wazuh-role-design.md
wazuh_enabled: true
# Baseline D1. El asistente instala el ultimo parche 4.14.x: si difiere, el gate falla.
wazuh_expected_version: "4.14.8"
wazuh_installer_url: "https://packages.wazuh.com/4.14/wazuh-install.sh"
wazuh_indexer_heap: "8g"
wazuh_retention_days: 30
# Directorio de secretos en el CONTROLADOR; debe quedar fuera del repositorio.
wazuh_secrets_dir: "~/soc-tesis-secrets/wazuh"
wazuh_relay_ip: "10.50.30.10"
wazuh_admin_cidr: "192.168.1.0/24"
wazuh_min_memory_mb: 7000
wazuh_min_disk_mb: 15000
wazuh_repo_root: "{{ (playbook_dir ~ '/..') | realpath }}"
wazuh_secrets_dir_real: "{{ wazuh_secrets_dir | expanduser | realpath }}"
```

- [ ] **Step 2: Tareas de instalación**

Reemplazar todo el contenido de `ansible/roles/wazuh/tasks/main.yml` por:

```yaml
---
# Rol wazuh: all-in-one con el asistente oficial (D5).
# Diseño: docs/superpowers/specs/2026-10-30-wazuh-role-design.md
- name: Omitir el rol si está deshabilitado (el preflight local no instala Wazuh)
  ansible.builtin.meta: end_role
  when: not (wazuh_enabled | bool)
  tags: [install, config, start]

# --- Instalación (único tag que descarga) ------------------------------------------
- name: Asegurar el directorio de centinelas
  ansible.builtin.file:
    path: /etc/soc-tesis
    state: directory
    mode: "0755"
  tags: [install, config]

- name: Leer si Wazuh ya está instalado
  ansible.builtin.stat:
    path: /var/ossec/bin/wazuh-control
  register: wazuh_control
  tags: [install]

- name: Comprobar la memoria mínima antes de instalar
  ansible.builtin.assert:
    that: ansible_memtotal_mb | int >= wazuh_min_memory_mb | int
    fail_msg: "Memoria insuficiente para el all-in-one: {{ ansible_memtotal_mb }} MiB (mínimo {{ wazuh_min_memory_mb }})."
  when: not wazuh_control.stat.exists
  tags: [install]

- name: Comprobar el disco libre antes de instalar
  ansible.builtin.assert:
    that: >-
      (ansible_facts.mounts | selectattr('mount', 'equalto', '/') | map(attribute='size_available') | first | default(0))
      / 1048576 >= wazuh_min_disk_mb | int
    fail_msg: "Disco libre insuficiente en / (mínimo {{ wazuh_min_disk_mb }} MiB)."
  when: not wazuh_control.stat.exists
  tags: [install]

- name: Persistir vm.max_map_count para el Indexer
  ansible.builtin.copy:
    dest: /etc/sysctl.d/99-soc-wazuh.conf
    content: |
      vm.max_map_count = 262144
    owner: root
    group: root
    mode: "0644"
  tags: [install]

- name: Aplicar vm.max_map_count (solo host real)
  ansible.builtin.command: sysctl -p /etc/sysctl.d/99-soc-wazuh.conf
  changed_when: false
  when: ansible_virtualization_type != 'docker'
  tags: [install]

- name: Leer vm.max_map_count vigente
  ansible.builtin.command: sysctl -n vm.max_map_count
  register: wazuh_map_count
  changed_when: false
  check_mode: false
  tags: [install]

- name: Comprobar el mínimo de vm.max_map_count del Indexer
  ansible.builtin.assert:
    that: wazuh_map_count.stdout | int >= 262144
    fail_msg: "vm.max_map_count={{ wazuh_map_count.stdout }}; el Indexer necesita 262144 como mínimo."
  tags: [install]

- name: Descargar el asistente de instalación
  ansible.builtin.get_url:
    url: "{{ wazuh_installer_url }}"
    dest: /root/wazuh-install.sh
    mode: "0700"
  when: not wazuh_control.stat.exists
  tags: [install]

- name: Instalar Wazuh all-in-one
  when: not wazuh_control.stat.exists
  tags: [install]
  block:
    - name: Ejecutar el asistente (-a); sin salida porque imprime las contraseñas
      ansible.builtin.command:
        cmd: bash /root/wazuh-install.sh -a
        chdir: /root
      async: 3600
      poll: 20
      changed_when: true
      no_log: true
      tags: [install]
  rescue:
    - name: Leer el final del log del asistente
      ansible.builtin.command: tail -n 40 /var/log/wazuh-install.log
      register: wazuh_install_tail
      changed_when: false
      failed_when: false
      tags: [install]

    - name: Fallo de la instalación de Wazuh
      ansible.builtin.fail:
        msg: "El asistente de Wazuh falló. Final del log: {{ wazuh_install_tail.stdout | default('(sin log)') }}"
      tags: [install]

# --- Gate de versión y verificación de componentes (siempre, solo lectura) -----------
- name: Leer la versión instalada de Wazuh
  ansible.builtin.command: /var/ossec/bin/wazuh-control info
  register: wazuh_control_info
  changed_when: false
  check_mode: false
  tags: [install]

- name: Exigir la versión esperada (gate de D1)
  ansible.builtin.assert:
    that:
      - ('WAZUH_VERSION="v' ~ wazuh_expected_version ~ '"') in wazuh_control_info.stdout
    fail_msg: >-
      La versión instalada de Wazuh no es la esperada ({{ wazuh_expected_version }}):
      desviación del baseline D1. Verifica la versión vigente y, si la aceptas, actualiza
      wazuh_expected_version (y el baseline) antes de reintentar.
  tags: [install]

- name: Comprobar que los cuatro componentes están instalados
  ansible.builtin.command: "dpkg -s {{ item }}"
  loop:
    - wazuh-manager
    - wazuh-indexer
    - wazuh-dashboard
    - filebeat
  changed_when: false
  check_mode: false
  tags: [install]

- name: Retener los paquetes de Wazuh en la versión instalada
  ansible.builtin.dpkg_selections:
    name: "{{ item }}"
    selection: hold
  loop:
    - wazuh-manager
    - wazuh-indexer
    - wazuh-dashboard
    - filebeat
  tags: [install]

- name: Marcar la instalación como verificada
  ansible.builtin.copy:
    dest: /etc/soc-tesis/wazuh-installed
    content: "version={{ wazuh_expected_version }}\n"
    owner: root
    group: root
    mode: "0644"
  tags: [install]
```

- [ ] **Step 3: Lint, sintaxis y contrato de tags**

Run: `cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'make ansible-lint syntax-check tags-contract'`
Expected: `Passed: 0 failure(s), 0 warning(s)` (puede aparecer el ruido no fatal `ArgsRule ... File name too long`), `tags-contract: ok (5 archivos de tareas)`. Corregir la causa de cualquier fallo; no desactivar reglas.

- [ ] **Step 4: Instalar de verdad (en segundo plano, 10 a 25 min)**

Run: `nix-shell --run 'make wazuh-apply TAGS=install' > <scratchpad>/wazuh-t2.log 2>&1; echo "rc=$?"` y esperar a que termine.
Expected: `rc=0`; en el log, la tarea del asistente en `changed`, el gate sin fallos y `failed=0`. Si el asistente falla, la salida incluye el final de `/var/log/wazuh-install.log`; **detenerse y reportar** (puede ser `policy-rc.d`, límites de systemd en el contenedor, requisitos de hardware o red). No relajar nada para forzar el verde.
Si el gate falla porque el asistente instaló otra versión (p. ej. 4.14.9), eso NO es un fallo del plan: reportar la versión instalada y esperar la decisión del operador (cambiar `wazuh_expected_version` o el baseline); no cambiar el valor por cuenta propia.

- [ ] **Step 5: Segunda pasada idempotente y checks 1 y 2**

Run: `nix-shell --run 'make wazuh-apply TAGS=install' 2>&1 | tail -n 15; WAZUH_CHECKS="1 2" nix-shell --run 'make wazuh-check'`
Expected: 2ª pasada con `changed=0` (el asistente se omite porque existe `wazuh-control`); `wazuh-check: ok` para los checks 1 (versión y 4 paquetes en hold) y 2 (cuatro servicios activos: el asistente los arranca con `systemctl`).

- [ ] **Step 6: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/roles/wazuh/defaults/main.yml ansible/roles/wazuh/tasks/main.yml
git commit -m "feat(ansible): rol wazuh, instalación con gate de versión y paquetes retenidos" -m "Asistente all-in-one en async con no_log, comprobaciones previas de memoria, disco y vm.max_map_count, gate de wazuh_expected_version (D1), verificación de los cuatro componentes, hold y centinela de instalación. wazuh_enabled=false omite el rol."
```

---

### Task 3: Rol `wazuh`, parte 2: configuración, secretos e ISM

**Files:**
- Modify: `ansible/roles/wazuh/tasks/main.yml` (agregar al final)
- Create: `ansible/roles/wazuh/handlers/main.yml`, `ansible/roles/wazuh/templates/ism-retention.json.j2`, `ansible/roles/wazuh/files/local_rules.xml`

**Interfaces:**
- Consumes: `/root/wazuh-install-files.tar` y el centinela `wazuh-installed` (Tarea 2); `authd.pass` en `{{ wazuh_secrets_dir_real }}`.
- Produces: centinela `/etc/soc-tesis/wazuh-secrets-handed-over`; tar traído a `{{ wazuh_secrets_dir_real }}/wazuh-install-files.tar` (0600); handlers `Reiniciar wazuh-manager` y `Reiniciar wazuh-indexer`.

- [ ] **Step 1: Handlers**

Crear `ansible/roles/wazuh/handlers/main.yml`:

```yaml
---
- name: Reiniciar wazuh-manager
  ansible.builtin.systemd_service:
    name: wazuh-manager
    state: restarted

- name: Reiniciar wazuh-indexer
  ansible.builtin.systemd_service:
    name: wazuh-indexer
    state: restarted
```

- [ ] **Step 2: Política ISM y gancho de reglas locales**

Crear `ansible/roles/wazuh/templates/ism-retention.json.j2`:

```
{
  "policy": {
    "description": "Retencion de wazuh-alerts-* a {{ wazuh_retention_days }} dias (D5)",
    "default_state": "retention_state",
    "states": [
      {
        "name": "retention_state",
        "actions": [],
        "transitions": [
          {
            "state_name": "delete_alerts",
            "conditions": { "min_index_age": "{{ wazuh_retention_days }}d" }
          }
        ]
      },
      {
        "name": "delete_alerts",
        "actions": [
          { "retry": { "count": 3, "backoff": "exponential", "delay": "1m" }, "delete": {} }
        ],
        "transitions": []
      }
    ],
    "ism_template": [
      { "index_patterns": ["wazuh-alerts-*"], "priority": 1 }
    ]
  }
}
```

Crear `ansible/roles/wazuh/files/local_rules.xml`:

```xml
<!--
  Reglas locales de SOC-TESIS. Rangos reservados (D5):
  Cowrie 100100-100199, Dionaea 100200-100299, Mailoney 100300-100399, Snare/Tanner 100400-100499.
  Este archivo es solo el punto de enganche: el contenido llega en la fase de reglas (wazuh-logtest).
-->
<group name="local,soc-tesis,">
</group>
```

- [ ] **Step 3: Agregar las tareas de `config` al final de `tasks/main.yml`**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS/ansible
cat >> roles/wazuh/tasks/main.yml <<'EOF'

# --- Configuración ----------------------------------------------------------------
- name: Leer si los secretos ya se entregaron
  ansible.builtin.stat:
    path: /etc/soc-tesis/wazuh-secrets-handed-over
  register: wazuh_handed_over
  tags: [config]

- name: Comprobar que el directorio de secretos está fuera del repositorio
  ansible.builtin.assert:
    that:
      - not ((wazuh_secrets_dir_real ~ '/').startswith(wazuh_repo_root ~ '/'))
    fail_msg: >-
      wazuh_secrets_dir ({{ wazuh_secrets_dir_real }}) está dentro del repositorio ({{ wazuh_repo_root }}):
      los secretos de Wazuh nunca pueden vivir en el repo.
  delegate_to: localhost
  become: false
  run_once: true
  tags: [config]

- name: Leer authd.pass en el controlador
  ansible.builtin.stat:
    path: "{{ wazuh_secrets_dir_real }}/authd.pass"
  register: wazuh_authd_local
  delegate_to: localhost
  become: false
  tags: [config]

- name: Exigir que authd.pass exista en el controlador
  ansible.builtin.assert:
    that: wazuh_authd_local.stat.exists
    fail_msg: "Falta {{ wazuh_secrets_dir_real }}/authd.pass (D8: se genera con openssl rand -base64 32)."
  tags: [config]

- name: Entregar authd.pass (contraseña de enrolamiento)
  ansible.builtin.copy:
    src: "{{ wazuh_secrets_dir_real }}/authd.pass"
    dest: /var/ossec/etc/authd.pass
    owner: root
    group: wazuh
    mode: "0640"
  no_log: true
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Activar la contraseña de enrolamiento en ossec.conf
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '<use_password>\s*no\s*</use_password>'
    replace: "<use_password>yes</use_password>"
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Apagar logall y logall_json (sin índice archives)
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: "<{{ item }}>\\s*yes\\s*</{{ item }}>"
    replace: "<{{ item }}>no</{{ item }}>"
  loop:
    - logall
    - logall_json
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Apagar la detección de vulnerabilidades
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '(<vulnerability-detection>\s*<enabled>)\s*yes\s*(</enabled>)'
    replace: '\1no\2'
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Apagar Active Response
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '(<active-response>\s*<disabled>)\s*no\s*(</disabled>)'
    replace: '\1yes\2'
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Leer ossec.conf para verificarlo
  ansible.builtin.slurp:
    src: /var/ossec/etc/ossec.conf
  register: wazuh_ossec
  check_mode: false
  tags: [config]

- name: Comprobar que ossec.conf quedó con los valores de D5
  ansible.builtin.assert:
    that:
      - (wazuh_ossec.content | b64decode) is search('<use_password>yes</use_password>')
      - (wazuh_ossec.content | b64decode) is search('<use_source_ip>no</use_source_ip>')
      - (wazuh_ossec.content | b64decode) is search('<logall>no</logall>')
      - (wazuh_ossec.content | b64decode) is search('<logall_json>no</logall_json>')
      - (wazuh_ossec.content | b64decode) is search('(?s)<vulnerability-detection>\s*<enabled>no</enabled>')
      - (wazuh_ossec.content | b64decode) is search('(?s)<active-response>\s*<disabled>yes</disabled>')
    fail_msg: >-
      ossec.conf no tiene los valores de D5 (las sustituciones no coincidieron con el formato
      del archivo instalado). Revisa /var/ossec/etc/ossec.conf y ajusta las expresiones del rol.
  tags: [config]

- name: Dejar el gancho de reglas locales
  ansible.builtin.copy:
    src: local_rules.xml
    dest: /var/ossec/etc/rules/local_rules.xml
    owner: wazuh
    group: wazuh
    mode: "0660"
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Dejar la API de Wazuh solo en loopback
  ansible.builtin.lineinfile:
    path: /var/ossec/api/configuration/api.yaml
    regexp: '^#?\s*host:'
    line: "host: ['127.0.0.1']"
    insertbefore: '^#?\s*port:'
    firstmatch: true
  notify: Reiniciar wazuh-manager
  tags: [config]

- name: Fijar el heap del Indexer
  ansible.builtin.lineinfile:
    path: /etc/wazuh-indexer/jvm.options
    regexp: "^{{ item }}"
    line: "{{ item }}{{ wazuh_indexer_heap }}"
  loop:
    - "-Xms"
    - "-Xmx"
  notify: Reiniciar wazuh-indexer
  tags: [config]

- name: Validar la configuración del Manager
  ansible.builtin.command: /var/ossec/bin/wazuh-analysisd -t
  changed_when: false
  check_mode: false
  tags: [config]

# --- Política ISM y entrega de secretos (una sola vez) -------------------------------
- name: Comprobar que el tar de contraseñas sigue en la VM
  ansible.builtin.stat:
    path: /root/wazuh-install-files.tar
  register: wazuh_tar
  tags: [config]

- name: Detener si faltan las contraseñas y los secretos no se entregaron
  ansible.builtin.fail:
    msg: >-
      No existe /root/wazuh-install-files.tar y no hay centinela wazuh-secrets-handed-over:
      no se puede aplicar la política ISM ni entregar los secretos. Reinstala o recupera el tar.
  when: not wazuh_handed_over.stat.exists and not wazuh_tar.stat.exists
  tags: [config]

- name: Esperar a que el Indexer responda
  ansible.builtin.wait_for:
    host: 127.0.0.1
    port: 9200
    timeout: 300
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Leer la contraseña de admin del Indexer (solo en memoria)
  ansible.builtin.shell: |
    set -o pipefail
    tar -axf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt -O \
      | grep -P "\'admin\'" -A 1 | tail -n 1 | sed -E "s/.*'([^']*)'.*/\1/"
  args:
    executable: /bin/bash
  register: wazuh_admin_pass
  changed_when: false
  no_log: true
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Escribir la política ISM (no contiene secretos)
  ansible.builtin.template:
    src: ism-retention.json.j2
    dest: /etc/soc-tesis/wazuh-ism-policy.json
    owner: root
    group: root
    mode: "0644"
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Aplicar la política ISM de retención
  ansible.builtin.command:
    argv:
      - curl
      - -sk
      - -K
      - "-"
      - -X
      - PUT
      - -H
      - "Content-Type: application/json"
      - --data-binary
      - "@/etc/soc-tesis/wazuh-ism-policy.json"
      - -o
      - /dev/null
      - -w
      - "%{http_code}"
      - https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-alert-retention-policy
    stdin: 'user = "admin:{{ wazuh_admin_pass.stdout }}"'
  register: wazuh_ism
  changed_when: wazuh_ism.stdout in ['200', '201']
  failed_when: wazuh_ism.stdout not in ['200', '201', '409']
  until: wazuh_ism.stdout in ['200', '201', '409']
  retries: 12
  delay: 10
  no_log: true
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Crear el directorio de secretos en el controlador
  ansible.builtin.file:
    path: "{{ wazuh_secrets_dir_real }}"
    state: directory
    mode: "0700"
  delegate_to: localhost
  become: false
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Traer wazuh-install-files.tar al controlador
  ansible.builtin.fetch:
    src: /root/wazuh-install-files.tar
    dest: "{{ wazuh_secrets_dir_real }}/wazuh-install-files.tar"
    flat: true
    validate_checksum: true
  no_log: true
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Dejar el tar traído solo para el operador
  ansible.builtin.file:
    path: "{{ wazuh_secrets_dir_real }}/wazuh-install-files.tar"
    mode: "0600"
  delegate_to: localhost
  become: false
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Calcular el sha256 del tar en la VM
  ansible.builtin.stat:
    path: /root/wazuh-install-files.tar
    checksum_algorithm: sha256
  register: wazuh_tar_remote
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Calcular el sha256 del tar en el controlador
  ansible.builtin.stat:
    path: "{{ wazuh_secrets_dir_real }}/wazuh-install-files.tar"
    checksum_algorithm: sha256
  register: wazuh_tar_local
  delegate_to: localhost
  become: false
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Exigir que las dos copias coincidan antes de destruir la de la VM
  ansible.builtin.assert:
    that:
      - wazuh_tar_remote.stat.checksum == wazuh_tar_local.stat.checksum
    fail_msg: "El tar traído al controlador no coincide con el de la VM: no se destruye el original."
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Destruir el tar de contraseñas en la VM
  ansible.builtin.command:
    cmd: shred -u /root/wazuh-install-files.tar
    removes: /root/wazuh-install-files.tar
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Borrar el log del asistente (contiene el resumen con contraseñas)
  ansible.builtin.file:
    path: /var/log/wazuh-install.log
    state: absent
  when: not wazuh_handed_over.stat.exists
  tags: [config]

- name: Marcar los secretos como entregados
  ansible.builtin.copy:
    dest: /etc/soc-tesis/wazuh-secrets-handed-over
    content: "retencion_dias={{ wazuh_retention_days }}\n"
    owner: root
    group: root
    mode: "0644"
  when: not wazuh_handed_over.stat.exists
  tags: [config]

# --- Firewall del host (solo host real, mismo patrón que logrelay) -------------------
- name: Permitir SSH desde la LAN del laboratorio (solo host real)
  community.general.ufw:
    rule: allow
    port: "22"
    proto: tcp
    src: "{{ wazuh_admin_cidr }}"
  when: ansible_virtualization_type != 'docker'
  tags: [config]

- name: Permitir 1514 y 1515 desde el relay y la LAN (solo host real)
  community.general.ufw:
    rule: allow
    port: "{{ item.0 }}"
    proto: tcp
    src: "{{ item.1 }}"
  loop: "{{ ['1514', '1515'] | product([wazuh_relay_ip, wazuh_admin_cidr]) | list }}"
  when: ansible_virtualization_type != 'docker'
  tags: [config]

- name: Permitir el Dashboard desde la LAN (solo host real)
  community.general.ufw:
    rule: allow
    port: "443"
    proto: tcp
    src: "{{ wazuh_admin_cidr }}"
  when: ansible_virtualization_type != 'docker'
  tags: [config]

- name: Política de entrada denegada (solo host real)
  community.general.ufw:
    default: deny
    direction: incoming
  when: ansible_virtualization_type != 'docker'
  tags: [config]

- name: Política de salida permitida (solo host real)
  community.general.ufw:
    default: allow
    direction: outgoing
  when: ansible_virtualization_type != 'docker'
  tags: [config]

- name: Activar UFW (solo host real)
  community.general.ufw:
    state: enabled
  when: ansible_virtualization_type != 'docker'
  tags: [config]
EOF
```

- [ ] **Step 4: Lint, sintaxis y contrato de tags**

Run: `nix-shell --run 'make ansible-lint syntax-check tags-contract'`
Expected: sin fallos. Puntos conocidos a corregir en su causa si aparecen: `risky-shell-pipe` (el `shell` ya lleva `set -o pipefail`), nombres de variables sin prefijo `wazuh_`, tareas sin tags.

- [ ] **Step 5: Aplicar la configuración (una sola vez, con el tar aún en la VM)**

Run: `nix-shell --run 'make wazuh-apply TAGS=install,config' > <scratchpad>/wazuh-t3.log 2>&1; echo "rc=$?"`
Expected: `rc=0`, `failed=0`, y el centinela `wazuh-secrets-handed-over` creado.
Puntos de fallo conocidos (resolver la causa, nunca el check):
- Si el `assert` de `ossec.conf` falla, las expresiones de `replace` no coinciden con el formato real: inspeccionar `docker exec soc-local-wazuh sed -n '1,80p' /var/ossec/etc/ossec.conf`, ajustar la expresión en el rol y reportar el formato real.
- Si `wazuh-analysisd -t` rechaza `local_rules.xml` con el grupo vacío, dejar en `files/local_rules.xml` solo el bloque de reglas de ejemplo mínimo que acepte Wazuh y reportarlo.
- Si la API del Indexer responde 400 a la política ISM, mirar el cuerpo con una llamada manual y ajustar la plantilla; reportarlo.
- Si `jvm.options` no existe en esa ruta, localizarlo con `docker exec soc-local-wazuh find /etc/wazuh-indexer -name 'jvm.options*'` y reportar.

- [ ] **Step 6: Idempotencia y checks 3 a 8**

Run: `nix-shell --run 'make wazuh-apply TAGS=install,config' 2>&1 | tail -n 8; WAZUH_CHECKS="3 4 5 6 7 8" nix-shell --run 'make wazuh-check'`
Expected: 2ª pasada con `changed=0` (las tareas de ISM, `fetch` y `shred` se saltan por el centinela); `wazuh-check: ok` para los checks 3 (puertos), 4 (`ossec.conf` y `analysisd -t`), 5 (`authd.pass`), 6 (heap `2g`), 7 (política ISM a 30 días) y 8 (higiene de secretos).
Si el check 3 falla porque 9300/1516/514 escuchan fuera de loopback, **no** cambiar el check: reportar qué puertos y en qué dirección (el bloqueo real lo hacen UFW y el NSG; puede requerir una decisión de diseño).

- [ ] **Step 7: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/roles/wazuh
git commit -m "feat(ansible): rol wazuh, configuración, política ISM y entrega de secretos" -m "authd.pass desde el controlador con la guarda fuera-del-repo, ossec.conf (D5) con assert de los valores, API en loopback, heap por variable, política ISM de 30 días y fetch con comparación de sha256 antes del shred, más UFW solo en host real."
```

---

### Task 4: Rol `wazuh`, parte 3: arranque y ensayo completo

**Files:**
- Modify: `ansible/roles/wazuh/tasks/main.yml` (agregar al final)

**Interfaces:**
- Consumes: todo lo anterior; `make wazuh-rehearse` (Tarea 1).
- Produces: tareas `start`; `make wazuh-rehearse` y `make wazuh-check` en verde (10 checks).

- [ ] **Step 1: Agregar las tareas de `start`**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS/ansible
cat >> roles/wazuh/tasks/main.yml <<'EOF'

# --- Arranque (nunca descarga) ------------------------------------------------------
- name: Habilitar y arrancar los servicios de Wazuh en orden
  ansible.builtin.systemd_service:
    name: "{{ item }}"
    enabled: true
    state: started
  loop:
    - wazuh-indexer
    - wazuh-manager
    - filebeat
    - wazuh-dashboard
  tags: [start]

- name: Esperar a que respondan los puertos de Wazuh
  ansible.builtin.wait_for:
    host: 127.0.0.1
    port: "{{ item }}"
    timeout: 300
  loop: [9200, 1514, 1515, 443]
  tags: [start]
EOF
```

- [ ] **Step 2: Lint, sintaxis y contrato de tags**

Run: `nix-shell --run 'make ansible-lint syntax-check tags-contract'`
Expected: sin fallos; `tags-contract` confirma que ninguna tarea `start` usa un módulo de descarga.

- [ ] **Step 3: Ensayo completo desde estado limpio**

Run (en segundo plano, salida a archivo; 25 a 40 min en total): `nix-shell --run 'make clean preflight && make wazuh-rehearse' > <scratchpad>/wazuh-t4.log 2>&1; echo "rc=$?"`
Expected, en orden:
- `preflight: Etapa 0 OK` (el rol `wazuh` se omite en el preflight).
- `wazuh-hostcheck: ok`.
- 1ª pasada `recap-check: ok (changed)`; 2ª `ok (nochange) changed=0`; `--check --diff` `ok (nochange)`.
- `wazuh-agent-fixture: ok (agente <versión> apuntando al relay 10.50.30.10)`.
- egreso cerrado; arranque 1ª `ok` y 2ª `ok (nochange) changed=0`.
- `wazuh-check`: todas las líneas `ok:` de los 10 checks y `wazuh-check: ok`.
- `wazuh-rehearse: ok` y `rc=0`.

Puntos de fallo conocidos (resolver la causa, nunca los checks):
- Check 9 (agente no aparece activo): comprobar `docker exec soc-local-honeyserver systemctl status wazuh-agent`, `docker exec soc-local-logrelay tail /var/log/soc-relay/stream.log` (deben verse sesiones `10.50.10.10 ... TCP 200` en 1514 y 1515) y `docker exec soc-local-wazuh tail /var/ossec/logs/ossec.log`. Si el relay no reenvía el enrolamiento, reportar con esos logs.
- Si el 2º `--tags start` no da `changed=0`, identificar la tarea que cambia (probablemente `enabled`/`state`) y corregir su causa.

- [ ] **Step 4: Regresión del resto del arnés**

Run: `nix-shell --run 'make common-check relay-check'`
Expected: `common-check: ok` y `relay-check: ok` (los contenedores siguen convergidos; el egreso quedó cerrado).

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/roles/wazuh/tasks/main.yml
git commit -m "feat(ansible): rol wazuh, arranque en orden con espera de puertos" -m "Tags start sin descargas: habilita y arranca indexer, manager, filebeat y dashboard y espera 9200, 1514, 1515 y 443. make wazuh-rehearse completo en verde con los 10 checks, incluido el agente enrolado a traves del relay."
```

---

### Task 5: `pin-check` detecta que el asistente instalaría otra versión (independiente de la Tarea 1)

**Files:**
- Modify: `ansible/local/scripts/pin-check.sh`

**Interfaces:**
- Consumes: `wazuh_expected_version` en `ansible/roles/wazuh/defaults/main.yml` (lo crea la Tarea 2); si el archivo aún no existe, esta parte del script se omite con un aviso, de modo que `make pin-check` no se rompe mientras tanto.
- Produces: la verificación extra de `make pin-check`; variable de entorno `PIN_CHECK_WAZUH_DEFAULTS` para probar otro archivo de defaults.

- [ ] **Step 1: Agregar la comprobación del índice de Wazuh**

En `ansible/local/scripts/pin-check.sh`, insertar justo **antes** del bloque final que empieza con `if [ "$fail" -ne 0 ]; then` este fragmento:

```bash
# --- Wazuh: el asistente instala el ULTIMO parche 4.14.x del indice, no uno fijo ---
# Si el ultimo parche difiere de wazuh_expected_version, el rol fallaria despues de 15 min de
# instalacion; aqui se detecta antes. Requiere Internet.
wazuh_defaults="${PIN_CHECK_WAZUH_DEFAULTS:-$root/roles/wazuh/defaults/main.yml}"
wazuh_index="https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-amd64/Packages"

if [ ! -f "$wazuh_defaults" ]; then
  echo "aviso: roles/wazuh/defaults/main.yml no existe todavia; se omite la comprobacion del indice de Wazuh"
else
  wazuh_want="$(sed -n 's/^wazuh_expected_version:[[:space:]]*"\([^"]*\)".*/\1/p' "$wazuh_defaults" | head -n1)"
  if [ -z "$wazuh_want" ]; then
    echo "FALLA: wazuh_expected_version no esta definida en $wazuh_defaults" >&2
    fail=1
  else
    indice="$(curl -fsSL --max-time 60 "$wazuh_index" 2>/dev/null || true)"
    if [ -z "$indice" ]; then
      indice="$(curl -fsSL --max-time 60 "${wazuh_index}.gz" 2>/dev/null | gzip -dc 2>/dev/null || true)"
    fi
    if [ -z "$indice" ]; then
      echo "FALLA: no se pudo leer el indice de Wazuh ($wazuh_index); pin-check necesita Internet" >&2
      fail=1
    else
      wazuh_latest="$(awk '/^Package: / {pkg=$2} /^Version: / {if (pkg == "wazuh-manager") print $2}' <<<"$indice" \
        | grep -E '^4\.14\.' | sort -V | tail -n 1)"
      if [ "$wazuh_latest" = "${wazuh_want}-1" ]; then
        echo "ok: el asistente de Wazuh instalaria ${wazuh_want} (ultimo wazuh-manager 4.14.x: $wazuh_latest)"
      else
        echo "FALLA: el ultimo wazuh-manager 4.14.x del indice es '${wazuh_latest:-ninguno}', no ${wazuh_want}-1" >&2
        echo "  el asistente instalaria esa version y el gate de versión del rol fallaria (baseline D1)." >&2
        echo "  decide si el baseline sube y actualiza wazuh_expected_version en roles/wazuh/defaults/main.yml" >&2
        fail=1
      fi
    fi
  fi
fi

```

- [ ] **Step 2: Lint estático**

Run: `cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'shellcheck local/scripts/pin-check.sh && echo OK'`
Expected: `OK`.

- [ ] **Step 3: Prueba negativa (versión que ya no es la última)**

Run:
```bash
tmp="$(mktemp -d)"; printf 'wazuh_expected_version: "4.14.0"\n' >"$tmp/defaults.yml"
PIN_CHECK_WAZUH_DEFAULTS="$tmp/defaults.yml" nix-shell --run 'make pin-check'; echo "rc=$?"; rm -rf "$tmp"
```
Expected: `FALLA: el ultimo wazuh-manager 4.14.x del indice es '<versión>', no 4.14.0-1`, `pin-check: FALLA` y `rc≠0`. (Requiere Internet.)

- [ ] **Step 4: Prueba positiva con la última versión real**

Run: determinar la última versión (`latest`) con el mismo comando del script y probar con ella:
```bash
latest="$(curl -fsSL https://packages.wazuh.com/4.x/apt/dists/stable/main/binary-amd64/Packages | awk '/^Package: /{p=$2} /^Version: /{if(p=="wazuh-manager")print $2}' | grep -E '^4\.14\.' | sort -V | tail -n1)"
tmp="$(mktemp -d)"; printf 'wazuh_expected_version: "%s"\n' "${latest%-1}" >"$tmp/defaults.yml"
PIN_CHECK_WAZUH_DEFAULTS="$tmp/defaults.yml" nix-shell --run 'make pin-check'; echo "rc=$?"; rm -rf "$tmp"
```
Expected: línea `ok: el asistente de Wazuh instalaria ...` y `rc=0` en la parte de Wazuh (el resto de `pin-check` también debe pasar). Si la URL del índice no responde (404), probar `Packages.gz`, localizar la ruta correcta con `curl -sI`, ajustar `wazuh_index` en el script y **reportar** la URL real.
Reportar además qué versión es hoy la última (`$latest`): es el dato que el operador necesita para decidir `wazuh_expected_version`.

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/local/scripts/pin-check.sh
git commit -m "feat(ansible): pin-check detecta que el asistente de Wazuh instalaría otra versión" -m "Compara el ultimo wazuh-manager 4.14.x del indice con wazuh_expected_version para fallar en la Etapa 0 y no tras 15 minutos de instalacion."
```

---

### Task 6: Documentación y refinamientos de la spec

**Files:**
- Modify: `ansible/PIPELINE.md`, `ansible/local/README.md`, `docs/superpowers/specs/2026-10-30-wazuh-role-design.md`

- [ ] **Step 1: `PIPELINE.md` (Etapas 4, 6 y 8)**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS
python3 - <<'EOF'
import pathlib
p = pathlib.Path("ansible/PIPELINE.md")
lines = p.read_text().split("\n")

# Etapa 8: fila de Wazuh despues de la fila de hora de common.
idx = [i for i, l in enumerate(lines) if l.startswith("| Hora (4 VMs) |")]
assert len(idx) == 1, idx
lines.insert(idx[0] + 1,
    "| Wazuh | `wazuh-control info` = versión esperada (gate D1); indexer, manager, filebeat y dashboard activos; "
    "1514/1515/443 abiertos y 9200/55000 solo en loopback; un agente de prueba aparece `Active` en `agent_control -l` "
    "a través del relay |")

# Etapa 6: nota del rol wazuh al final de la seccion (antes de la Etapa 7).
fin = [i for i, l in enumerate(lines) if l.startswith("## Etapa 7")]
assert len(fin) == 1, fin
nota = [
    "### Notas del rol `wazuh` (Etapa 6)",
    "- Requiere en el controlador `~/soc-tesis-secrets/wazuh/authd.pass` (D8, `openssl rand -base64 32`); el rol falla si falta o si ese directorio está dentro del repo.",
    "- La instalación con el asistente descarga más de 1 GB y tarda de 10 a 25 minutos: planear la ventana de egreso. Antes, `make pin-check` (la versión que instala el asistente puede diferir del baseline).",
    "- Si el gate de versión falla, es una desviación del baseline D1: se decide si sube `wazuh_expected_version`; el rol no instala nada más.",
    "- Al terminar, `wazuh-install-files.tar` (contraseñas de admin/API) queda en el controlador (`0600`) y se destruye en la VM. Cambiar la contraseña de admin es un paso manual posterior.",
    "",
]
lines[fin[0]:fin[0]] = nota
p.write_text("\n".join(lines))
print("PIPELINE.md actualizado")
EOF
git diff --stat ansible/PIPELINE.md
```
Expected: `PIPELINE.md actualizado`.

- [ ] **Step 2: Sección en el README local**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS/ansible
cat >> local/README.md <<'EOF'

## Rol wazuh: `make wazuh-rehearse` y `make wazuh-check`

El all-in-one real (Manager + Indexer + Dashboard) corre en el contenedor `wazuh`. **No** forma parte de `preflight`: descarga más de 1 GB y tarda de 10 a 25 minutos, así que el inventario local marca `wazuh_enabled: false` y el rol se omite. Úsalo cuando toques el rol y antes del primer ciclo real.

Requisitos del anfitrión (`make wazuh-hostcheck`, solo lee): `MemAvailable` suficiente, `vm.max_map_count` ≥ 262144 y disco libre. El heap del Indexer se sobrescribe a `2g` en local (el real, `8g`, no cabe en un equipo compartido).

Flujo: `make clean preflight` y luego `make wazuh-rehearse`: 1ª pasada `install,config` (exige `changed`), 2ª pasada (`changed=0`), `--check --diff`, un agente de prueba instalado en `honeyserver` y enrolado **a través del relay** (D4), egreso cerrado, `--tags start` dos veces y `make wazuh-check`. Para iterar: `make wazuh-apply TAGS=install` y `WAZUH_CHECKS="1 2" make wazuh-check`.

Los secretos del ensayo viven en `/tmp/soc-local-secrets/` (desechables, fuera del repo: así se ejerce la guarda del rol); `make clean` los borra.

Qué comprueba `wazuh-check`: (1) versión y paquetes en `hold`, (2) servicios activos, (3) puertos (1514/1515/443 abiertos; 9200 y 55000 solo en loopback; 9300, 1516, 514 y 1514/udp cerrados), (4) `ossec.conf` con los valores de D5 y `wazuh-analysisd -t`, (5) `authd.pass`, (6) heap, (7) política ISM de 30 días, (8) que el tar y el log del asistente no queden en la VM, (9) agente activo a través del relay, (10) que el gate de versión falle con una versión distinta.

Qué NO valida: UFW real y el NSG de Azure, el heap real de 8g en `Standard_B4as_v2`, el arranque en frío tras `az vm start`, que los datos del Indexer sobrevivan a `deallocate`/`start`, y el acceso al Dashboard desde la LAN por el túnel. El agente de `honeyserver` es un fixture del arnés: el rol `honeypot` lo instalará de verdad.
EOF
```

- [ ] **Step 3: Parchar la spec con los refinamientos**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS
python3 - <<'EOF'
import pathlib
p = pathlib.Path("docs/superpowers/specs/2026-10-30-wazuh-role-design.md")
s = p.read_text()

def rep(old, new):
    global s
    assert s.count(old) == 1, (old, s.count(old))
    s = s.replace(old, new)

rep("protegido por el centinela `/etc/soc-tesis/wazuh-installed` (se escribe solo tras pasar el gate de versión)",
    "solo si no existe `/var/ossec/bin/wazuh-control`; el centinela `/etc/soc-tesis/wazuh-installed` se escribe solo tras pasar el gate de versión y comprobar que los cuatro paquetes están instalados")

rep("| Instalación a medias | Sin centinela y con restos en `/var/ossec`, el rol se detiene y pide desinstalar a mano con `wazuh-install.sh -u`; no borra nada solo. |",
    "| Instalación a medias | Con `/var/ossec` presente y sin centinela, el rol no reinstala: reejecuta el gate de versión y comprueba que los cuatro paquetes estén instalados; si ambos pasan, escribe el centinela (reanudación, p. ej. tras subir `wazuh_expected_version`); si no, se detiene y pide desinstalar a mano con `wazuh-install.sh -u`. No borra nada solo. |")

rep("| El asistente instala otro parche | Falla *después* de instalar con un mensaje de desviación de D1. El `pin-check` del lote de pendientes debe consultar el índice `packages.wazuh.com/4.x/apt` para verlo en la Etapa 0. |",
    "| El asistente instala otro parche | Falla *después* de instalar con un mensaje de desviación de D1. `make pin-check` consulta el índice `packages.wazuh.com/4.x/apt` y compara el último `wazuh-manager` 4.14.x con `wazuh_expected_version`, para verlo en la Etapa 0. |")

p.write_text(s)
print("spec parchada")
EOF
git diff --stat
```
Expected: `spec parchada`.

- [ ] **Step 4: Escaneo de secretos y commit**

```bash
cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'make secret-scan'
cd .. && git add ansible/PIPELINE.md ansible/local/README.md docs/superpowers/specs/2026-10-30-wazuh-role-design.md
git commit -m "docs(ansible): wazuh-rehearse, notas de la Etapa 6 y refinamientos de la spec" -m "Fila de Wazuh en la Etapa 8, requisitos del rol en la Etapa 6, README del ensayo y la semantica de reanudacion del instalador."
```
Expected: `secret-scan: ok (...)` y el commit creado.

---

## Self-Review

**Cobertura de la spec:**
- §2 decisiones: asistente online + gate (Tarea 2 pasos 2 y 4); all-in-one completo en el ensayo (Tareas 1 y 4); target aparte (`wazuh-rehearse`, `wazuh_enabled: false` en el inventario, Tarea 1); secretos movidos por Ansible fuera del repo (Tarea 3); check 9 (Tarea 1 `c9` + fixture, Tarea 4). ✔
- §3 variables: Tarea 2 paso 1 (todas; `wazuh_enabled` y el heap en el inventario local, Tarea 1 paso 6). ✔
- §4 `install`: comprobaciones previas, `sysctl`, instalador `-a` con `no_log`, gate, hold y centinela → Tarea 2 paso 2. ✔
- §4 `config`: `authd.pass`, `ossec.conf`, gancho de reglas, API en loopback, heap, ISM, `fetch` + `sha256` + `shred`, UFW → Tarea 3. ✔
- §4 `start` → Tarea 4 paso 1. ✔ `wazuh_enabled: false` termina el rol → Tarea 2 paso 2 (primera tarea). ✔
- §5 errores: otro parche (gate + `pin-check`, Tareas 2 y 5), instalación a medias (reanudación, refinada en Tarea 6), RAM/disco/`vm.max_map_count` (Tarea 2), fallo de `fetch` o `sha256` (Tarea 3, `assert` antes de `shred`), API del Indexer (reintentos, Tarea 3), reejecución (centinela), arranque en frío (`wait_for`, Tarea 4), log del asistente (borrado + check 8). ✔
- §6 pruebas: los 10 checks y el flujo `wazuh-rehearse` → Tareas 1 y 4. ✔
- §7 criterio de listo → Tarea 4 pasos 3 y 4; documentación → Tarea 6. ✔
- §8 fuera de alcance: no se escribe contenido de reglas, no se cambia la contraseña de admin, no hay agentes Windows/Ubuntu. ✔

**Escaneo de placeholders:** sin TBD/TODO. Los puntos que dependen del formato real de los archivos instalados (`ossec.conf`, `api.yaml`, `jvm.options`, respuesta de la API ISM) se resuelven con un `assert` en el rol y un paso de descubrimiento con el criterio explícito de qué hacer en cada caso, no con texto vago.

**Consistencia de nombres:** `wazuh_expected_version` (defaults) ↔ `wazuh-check.sh`, `wazuh-agent-fixture.sh`, `pin-check.sh`; centinelas `wazuh-installed` y `wazuh-secrets-handed-over` ↔ tareas `config`; handlers `Reiniciar wazuh-manager`/`Reiniciar wazuh-indexer` ↔ `notify`; `wazuh_secrets_dir_real` (defaults) ↔ guarda, `copy`, `fetch`; `/tmp/soc-local-secrets` ↔ inventario local, `gen-wazuh-secrets.sh`, `wazuh-check.sh`, `clean`; mensaje `desviación del baseline D1` ↔ `c10`.

**Riesgos conocidos no verificables sin ejecutar:** comportamiento exacto del asistente dentro de un contenedor systemd (límites, `policy-rc.d`), formato real de los archivos de configuración instalados, forma exacta de la respuesta GET de la política ISM y si 9300/1516/514 escuchan fuera de loopback. El plan los trata con pasos de descubrimiento y criterios de parada, no con suposiciones silenciosas.
