# Pipeline de despliegue: de `terraform apply` a VMs configuradas

Basado en ADR-006 **con la enmienda E1** (2026-10-27, §10 del ADR). Cada etapa tiene un comando, una verificación y un gate. Si una verificación falla, el pipeline se detiene ahí.

Leyenda: **[AUTO]** se puede automatizar entera · **[GATE]** necesita autorización humana · **[MANUAL]** queda fuera de la automatización.

Regla general: cada verificación termina con exit ≠ 0 si falla. Los gates se basan en códigos de salida, nunca en buscar texto en stdout.

## Etapa 0 · Pre-vuelo (local, sin costo) [AUTO]
| Paso | Verificación |
|---|---|
| `terraform fmt -check` y `validate` en `terraform/lab` | exit 0 |
| `ansible-lint` y `ansible-playbook --syntax-check` | exit 0 |
| Contrato de tags: `ansible-playbook site.yml --list-tasks --tags start` | ningún módulo de descarga (`apt`, `get_url`, `docker_image`, `pip`, `git`) |
| **Ensayo local** (Fase 0 del ADR), `site.yml` dos veces | 1ª pasada con cambios, 2ª con `changed=0` |
| `ansible-playbook --check --diff` **después** de converger (control de drift) | sin errores y sin cambios |
| Escaneo de secretos en el diff (PSK, llaves privadas) | 0 hallazgos |
| `make pin-check` (requiere Internet) | los paquetes de NGINX tienen la versión fijada en `jammy`. Correr justo antes de la Etapa 6 y siempre que pase tiempo entre el baseline y el despliegue: los pines de apt se retiran del archivo (ocurrió con NGINX 14.21 → 14.22). |
| `az account show` | sesión vigente y suscripción correcta |
| Hora local | antes de las 20:30 (el auto-shutdown de las 22:00 no debe cortar el ciclo) |

**Gate:** si la 2ª pasada local no da `changed=0`, no se avanza a Terraform.

`unattended-upgrades` ya no es un riesgo abierto: el rol `common` desactiva los timers `apt-daily*` y la actualización automática (ver `roles/common` y `make common-check`).

## Etapa 1 · Plan de Terraform [AUTO] + autorización [GATE]
1. `umask 077; terraform plan -out=/tmp/tfplan` con `maintenance_egress=false`.
2. Comprobaciones automáticas sobre `terraform show -json /tmp/tfplan`. Se valida por tipo y nombre, no por número total de recursos:
   - no hay secretos en el plan,
   - no hay ninguna regla `Allow-Out-Maintenance-Egress`,
   - hay exactamente 4 `azurerm_linux_virtual_machine`,
   - `Allow-Lab-Admin-SSH` (22): exactamente tres reglas, una por NSG (`nsg-vpn`→`10.50.20.10`, `nsg-logrelay`→`10.50.30.10`, `nsg-wazuh`→`10.50.40.10`), solo desde `lab_cidr`,
   - `Allow-Lab-Admin-SSH-22222` solo desde `lab_cidr` hacia `10.50.10.10`,
   - honeyserver tiene `custom_data` que mueve sshd al 22222 (E1-2). Se lee del JSON del plan (el valor sensible viene en `after`): debe existir `10-admin-port.conf` y el conjunto de líneas `Port` debe ser exactamente `{22222}`. Si no aparece, el check falla; nunca pasa por omisión.
3. **Gate:** el operador escribe `AUTORIZO terraform apply de /tmp/tfplan`. Desde aquí hay costo. El gate guarda el sha256 del plan en `/tmp/tfplan.authorized` (0600) para que la Etapa 2 compruebe que aplica el plan autorizado.

`make stage1` (en `ansible/`) encadena `azure-session` → `time-guard` → `plan` (incluye `plan-check`) → `gate-apply`. Requiere `EXPECTED_AZ_SUBSCRIPTION_NAME` y TTY. Para solo planear sin gate ni guarda de hora: `make azure-session plan`. El plan y su JSON contienen secretos (p. ej. `admin_password`): 0600, JSON temporal borrado con `trap`, `/tmp/tfplan` borrado tras el apply.

## Etapa 2 · Apply y validación de infraestructura [AUTO]
| Paso | Verificación |
|---|---|
| `terraform apply /tmp/tfplan`, luego `rm /tmp/tfplan` | exit 0 |
| `terraform output` | existen `strongswan_public_ip`, `private_ips` y `vm_ids` |
| `az vm list -d` | las 4 VMs en `PowerState/running` |
| Auto-shutdown 22:00 | presente en las 4 VMs |
| **SSH real fuera del 22 público de honeyserver** (E1-2): `nc -w5 <honeyserver_public_ip> 22` | no responde ningún banner `SSH-2.0-OpenSSH`. Si aparece uno, se aborta y se hace `az vm deallocate` de honeyserver |
| `terraform plan` inmediato | "No changes" |

## Etapa 3 · Ventana de mantenimiento: abrir egreso [GATE]
Se abre **antes** del bootstrap porque la VM strongSwan necesita instalar paquetes para levantar el túnel (E1-1).
1. Autorización escrita del operador.
2. `terraform apply -var maintenance_egress=true`.
3. Verificación: el diff solo agrega las 4 reglas `Allow-Out-Maintenance-Egress` (una por NSG).

Durante la ventana ningún servicio del honeypot está activo (E1-3). Honeyserver solo tiene sshd en el 22222, accesible únicamente desde `lab_cidr`.

## Etapa 4 · Bootstrap por `run-command` (una sola vez) [MANUAL, con ayuda]
Es el único tramo con secretos. Se hace con managed run command (`az vm run-command create`), no con `invoke`.

**4a · Huellas de host (las 4 VMs).** El script remoto ejecuta `ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub`. Las huellas se guardan en un `known_hosts` **fuera del repo** (honeyserver como `[10.50.10.10]:22222`). `host_key_checking` sigue en `True` (E1-4).

**4b · VM strongSwan como respondedora.**
1. Se instala `strongswan-swanctl` y se activa `net.ipv4.ip_forward=1`.
2. Se escribe un `swanctl.conf` mínimo de respondedor (sin `start_action`).
3. Se entrega el PSK, generado en la Pi con `openssl rand -hex 32` y guardado en `0600` root.

Reglas para el PSK (E1-5):
- va por `--protected-parameters`, y el valor se lee del archivo `0600` dentro de un script local; **nunca** se escribe literal en la línea de comandos,
- el script remoto no usa `set -x`, no imprime el valor y escribe con `install -m 0600`,
- al terminar: `az vm run-command delete`.

| Verificación | Criterio |
|---|---|
| Archivo de secretos en la VM | `0600`, propiedad de root |
| `az vm run-command show --instance-view` | no contiene el PSK |
| `grep` del PSK en el repo, en el plan, en `~/.zsh_history`/`~/.bash_history` y en los logs | 0 resultados |
| `swanctl --list-conns` en la VM | la conexión aparece cargada |

## Etapa 5 · Túnel IPsec (C4) [GATE]
1. Se configura la Pi: strongSwan iniciador, xfrm0, ruta y MSS clamp. Esto queda fuera de Ansible (A2).
2. Verificación: `swanctl --list-sas` con la SA establecida, y `ping 10.50.20.10` desde la Pi y desde 192.168.1.73.
3. Con las huellas de 4a: `ssh -o StrictHostKeyChecking=yes` a las 4 VMs.

**Gate:** sin túnel no se continúa.

## Etapa 6 · Ansible: instalación y configuración [AUTO]
Desde 192.168.1.73, con `ANSIBLE_PRIVATE_KEY_FILE` y el `known_hosts` de la Etapa 4a:

| Paso | Verificación |
|---|---|
| `ansible all -m ping` | 4 de 4 `pong` (honeyserver por el 22222) |
| `site.yml --tags install,config` | `failed=0 unreachable=0` |
| `ansible all -m ping` **justo después** de `--tags install,config` | 4 de 4 `pong`; detecta un bloqueo de UFW/sshd antes de seguir |
| 2ª pasada | `changed=0` |
| **Honeypot apagado** (E1-3): `systemctl is-active` y `docker ps` en honeyserver | ningún servicio del señuelo activo ni habilitado |

Orden de roles: `common → strongswan → wazuh → logrelay → honeypot`. En la VM strongSwan, el rol converge sobre lo que dejó el bootstrap. **No toca** el archivo de secretos de swanctl.

**Rescate si UFW corta el SSH de logrelay.** Si el `ansible all -m ping` posterior a `--tags install,config` falla solo en `logrelay`, ejecutar desde el operador `az vm run-command invoke` sobre la VM logrelay con `--scripts "ufw disable"` (sin pegar IDs ni secretos), confirmar que vuelve el SSH, corregir la regla de UFW del rol y reintentar. `run-command` usa el agente de la VM y no depende del túnel ni de sshd.

## Etapa 7 · Cierre de egreso [GATE + verificación AUTO]
1. Esperar a que no haya descargas en curso: la NSG es stateful y no corta los flujos ya establecidos.
2. `terraform apply -var maintenance_egress=false`.
3. Verificaciones (E1-6):
   - el plan siguiente no contiene `Allow-Out-Maintenance-Egress`,
   - desde honeyserver, por el túnel, fallan `curl -m5 http://1.1.1.1` y `curl -m5 https://example.com`. Los destinos no están en Azure, para que `Allow-Out-AzureCloud-443` no dé un falso positivo,
   - la conectividad por el túnel sigue funcionando.

**Gate duro:** no se ejecuta la Etapa 8 si este cierre falla.

## Etapa 8 · Arranque de servicios [AUTO]
`site.yml --tags start`, con el honeypot al final. El tag `start` no descarga nada (lo verificó la Etapa 0).

| Servicio | Verificación |
|---|---|
| strongSwan (VM) | SA activa |
| Wazuh | puertos y servicio arriba |
| logrelay | desde honeyserver, `nc -zv 10.50.30.10 1514` y `1515` conectan, y `/var/log/soc-relay/stream.log` registra `10.50.10.10 ... TCP 200` |
| Honeypot | el señuelo escucha en el 22 y la administración sigue en el 22222 |
| Hora (4 VMs) | `timedatectl show -p NTPSynchronized --value` = `yes`; el rol `common` lo exige en el tag `start` (12 reintentos de 10 s) y falla si no llega. Depende de que la imagen sincronice sin egreso (PTP de Hyper-V); si no, decidir aquí si se configura chrony |

## Etapa 9 · Aceptación de punta a punta [AUTO]
Evento de prueba: una conexión al señuelo. En el relay (L4, solo tráfico cifrado) únicamente se ve la sesión del agente en `stream.log`, no el evento; el evento tiene que aparecer en Wazuh con la identidad del agente y quedar como alerta. El Manager ve la IP del relay (10.50.30.10) como origen.

Comprobaciones finales:
- 2ª pasada completa de Ansible con `changed=0`,
- `terraform plan` con "No changes",
- `az vm deallocate` y `az vm start` en orden restauran todo sin intervención (ciclo de la Fase 8 del ADR), incluido el honeypot **sin** egreso,
- reporte de evidencia (salidas, versiones, hora) en `evidence/`, sin secretos.

**El despliegue está correcto cuando** pasan las etapas 2, 4, 5, 6, 7, 8 y 9, el egreso está cerrado y la 2ª pasada da `changed=0`.

## Qué se replica en la rama `practica/ansible-local`
- **Etapas 0, 6, 8 y 9** en un entorno local. Puede ser con contenedores con systemd (`jrei/systemd-ubuntu:22.04`, `--privileged --cgroupns=host`) o con VMs locales (libvirt/QEMU). Las VMs se acercan más a Azure.
- **Etapa 7** simulada con dos redes Docker: una con salida para instalar y otra `internal` para operar. Se comprueba que honeyserver pierde la salida a Internet.
- **Etapa 4a** simulada: `known_hosts` desechable, regenerado por script en cada recreación.
- **Gates**: `Makefile` con un target por etapa, encadenados por dependencias. Cada target falla con exit ≠ 0.
- **No se replican** las Etapas 1 a 5 (Terraform, Azure, `run-command` y el túnel real). Se cubren con `terraform plan` y checks sobre el JSON del plan.
- **No se valida localmente** (E1-7): xfrm/IPsec real, `ip_forward` del host en contenedores, NSG de Azure, el agente de `run-command`, ni Docker-in-Docker del honeypot si se usan contenedores. Las tareas que no aplican en contenedor llevan `when: ansible_virtualization_type != 'docker'`. Se verifican en el primer ciclo real.

## Estado del entorno (2026-10-29)
- Docker instalado.
- `ansible`, `ansible-lint` y `molecule` no instalados (en NixOS conviene `nix-shell` o un `flake`).
- Orquestación propuesta: `Makefile` + Docker Compose. Molecule solo si hace falta.
- `custom_data` de honeyserver (E1-2) implementado en `terraform/lab/vms.tf` (sshd en 22222); verificado contra el plan real de Azure (Etapa 1); sin desplegar. La Etapa 2 lo confirma con el banner del 22 público.
- Etapas 0 y 1 implementadas en `ansible/` (`make preflight`, `make stage1`). Etapa 1 probada con plan real (checks a–f en verde); el gate `time-guard` + `gate-apply` en cadena se prueba en la primera corrida completa de `make stage1`.
