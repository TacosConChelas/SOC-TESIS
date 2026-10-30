# Ensayo local de Ansible — Etapa 0

Replica en contenedores lo que `ansible/` hará en las VMs de Azure (ADR-006
Fase 0 y E1-7). No toca Azure ni Terraform.

## Requisitos

- Docker + Compose.
- `nix-shell` (el shell trae `ansible`, `ansible-lint`, `shellcheck`, `openssh`
  y `python3` con PyYAML).
- Terraform **>= 1.16.3** del host: el pin de nixpkgs trae 1.15.3 y
  `terraform/lab/versions.tf` exige 1.16.3, así que no se incluye en el shell.

```bash
cd ansible
nix-shell          # entra al entorno
make preflight     # Etapa 0 completa
```

`make preflight` encadena `lint` → `tags-contract` → `secret-scan` →
`secret-scan-selftest` → `rehearse`.

## Contenedores

| Servicio | IP simulada | sshd |
|---|---|---|
| strongswan | 10.50.20.10 | 22 |
| wazuh | 10.50.40.10 | 22 |
| logrelay | 10.50.30.10 | 22 |
| honeyserver | 10.50.10.10 | 22222 (el 22 es el señuelo) |

Son `jrei/systemd-ubuntu:22.04` con `openssh-server`, `privileged`,
`cgroup=host` y `/sys/fs/cgroup` **rw** (con `ro` systemd no arranca). Las
claves de host se borran en el build y se regeneran en cada arranque, para que
`known_hosts` sea realmente desechable.

`make up` reconstruye la imagen pero arranca con `--no-recreate`: los
contenedores existentes conservan su ID y la convergencia (BuildKit cambia el
ID de la imagen en cada build). Para aplicar cambios de `Dockerfile` o
`entrypoint.sh` hay que hacer `make clean` y luego `make up`.

Dos redes:

- `operate` (`internal: true`, 10.50.0.0/16): las IPs simuladas, sin egreso.
- `install` (bridge, 172.28.0.0/24): se conecta/desconecta para simular la
  ventana de egreso de las Etapas 3 y 7.

```bash
make toggle-install   # abre egreso
make toggle-operate   # lo cierra
make netcheck         # falla si algún contenedor alcanza 1.1.1.1 o example.com
```

## Targets

| Target | Qué hace |
|---|---|
| `lint` | `terraform fmt -check`, `validate` (copia temporal, backend=false), `ansible-lint`, `--syntax-check` |
| `tags-contract` | E1-8: tags ∈ {install,config,start} y `start` sin módulos de descarga |
| `secret-scan` | reglas A/B sobre todo el árbol, C con lista de excepciones |
| `secret-scan-selftest` | planta 4 secretos falsos y exige que el escaneo falle |
| `up` / `down` | construye/arranca y destruye los contenedores |
| `known-hosts` | simula la Etapa 4a (huellas de host desechables) |
| `ping` | `ansible all -m ping` (4 `pong`) |
| `rehearse` | 1ª pasada con cambios, 2ª `changed=0`, `--check --diff` limpio, cierre de egreso y `netcheck` |
| `pin-check` | verifica con `apt-cache madison` que los pines de apt de los roles existan hoy en jammy (requiere Internet; **fuera** de `preflight`) |
| `preflight` | todo lo anterior |
| `azure-session` / `time-guard` | `az account show` y corte de las 20:30; **fuera** de `preflight` |

## Etapa 1 — plan y autorización (sin apply)

| Target | Qué hace |
|---|---|
| `azure-session` | exige `EXPECTED_AZ_SUBSCRIPTION_NAME` (variable de entorno, nunca en el repo), `az` con sesión vigente y esa suscripción en estado `Enabled`. No imprime IDs. |
| `time-guard` | falla a partir de 20:30 (E1-9). Se prueba sin esperar: `TIMEGUARD_NOW=20:30 make time-guard`. |
| `plan` | `umask 077; terraform plan -input=false -lock=false -var maintenance_egress=false -out=/tmp/tfplan`; deriva el JSON a un temporal 0600, corre `plan-check` y lo borra con `trap`. La salida del plan no se imprime y las rutas del home se redactan. Un plan nuevo borra `/tmp/tfplan.authorized`. |
| `plan-check` | valida un JSON de plan (`PLAN_JSON=... make plan-check`, por defecto `/tmp/tfplan.json`) por tipo y nombre: (a) sin secretos, (b) sin `Allow-Out-Maintenance-Egress`, (c) 4 VMs, (d) SSH 22 solo desde `lab_cidr` a 10.50.20.10/30.10/40.10, (e) 22222 solo desde `lab_cidr` a 10.50.10.10, (f) `custom_data` de honeyserver fija `Port 22222`. |
| `plan-check-selftest` | plan sintético control (debe pasar) + un caso roto por check a–f (cada uno falla nombrando su check). Sin datos reales (`203.0.113.0/24`). |
| `gate-apply` | exige TTY y la frase exacta `AUTORIZO terraform apply de /tmp/tfplan`; escribe el `sha256` en `/tmp/tfplan.authorized` (0600) para que la Etapa 2 compruebe que aplica el plan autorizado. **No aplica nada.** |
| `stage1` | `azure-session` → `time-guard` → `plan` (incluye `plan-check`) → `gate-apply`. Si algo falla, no sigue. |

`make plan` no ejecuta `terraform init`: si falta `terraform/lab/.terraform`, falla y pide hacerlo una vez a mano (así no se toca el repo).

### Lo que la Etapa 1 NO verifica

Que Azure acepte las SKU o la cuota vigente, que la imagen Ubuntu siga disponible, precios, ni que el `apply` funcione. Todo eso se descubre en la Etapa 2 (con costo). El plan tampoco prueba el banner del 22 público (E1-2): eso es posterior al apply.

### Check (f) y `custom_data`

azurerm 5.8.0 marca `custom_data` como `sensitive`. Se verifica sobre `resource_changes[].change.after.custom_data` del JSON del plan (local no redacta esos valores; por eso el plan y el JSON son 0600) decodificando base64. Si el valor no apareciera, el check **falla** en vez de pasar en silencio.

## Rutas y secretos

- `local/.keys/` (llave desechable, 0600), `local/.known_hosts` y
  `local/.artifacts/` están en `local/.gitignore`.
- El Makefile exporta `ANSIBLE_INVENTORY`, `ANSIBLE_PRIVATE_KEY_FILE`,
  `ANSIBLE_USER_KNOWN_HOSTS_FILE` y `ANSIBLE_SSH_ARGS` con rutas absolutas, para
  que ssh no lea `~/.ssh/known_hosts` del operador.
- `local/secret-scan.allow` exceptúa **solo** la regla C (64 hex) en rutas que
  guardan hashes sha256 ya registrados (`evidence/`, `scrape_2_5/`, `.firecrawl/`,
  `graphify-out/`, `config/`, `.env.example`, `docker-compose.test.yml` y el
  lockfile de Terraform). Las reglas A (PEM) y B (PSK/secret literal) cubren el
  árbol completo sin excepciones.

## Lo que NO se valida localmente (E1-7)

Copia de `PIPELINE.md`: xfrm/IPsec real, `ip_forward` del host dentro de
contenedores, NSG de Azure, el agente de `run-command`, Docker-in-Docker del
honeypot, el túnel real y todo lo de Terraform/Azure (Etapas 1 a 5). Las tareas
que no aplican en contenedor llevan
`when: ansible_virtualization_type != 'docker'` y se verifican en el primer
ciclo real.

## Avisos

- Si el túnel real está arriba en este host, la subred `10.50.0.0/16` de Docker
  puede chocar con la ruta del túnel. Baja el túnel o cambia la subred de
  `operate` antes de ensayar.
- `ansible-lint` corre con el perfil `production`; `site.yml` necesitó nombres
  de play para pasar.
- El rol `wazuh` sigue siendo un marcador (P-A1): no instala ni arranca nada
  real todavía.

## Rol logrelay: `make relay-check`

Verifica el rol `logrelay` (NGINX `stream`, D4) sobre los contenedores ya convergidos, por lo que se corre **después** de `make rehearse` (o dentro de `make preflight`, que ya lo incluye). La versión de NGINX está fijada en `roles/logrelay/defaults/main.yml` (`logrelay_nginx_version`); si `apt` no la encuentra, el baseline D1 debe re-verificarse.

Qué hace: levanta un Manager falso (eco TCP) en el contenedor `wazuh` y comprueba (1) que `honeyserver` llega por el relay a 1514 y 1515, (2) que `strongswan` queda bloqueado por `deny all`, (3) que el log `/var/log/soc-relay/stream.log` registra las sesiones (200/403) sin su contenido, (4) `nginx -t`, versión fijada y los paquetes retenidos, (5) `logrotate -d`.

Qué NO valida: reglas y activación reales de UFW (en contenedor se omiten), el NSG de Azure y el protocolo real del agente Wazuh (enrolamiento TLS en 1515, cifrado en 1514). Eso se verifica en el primer ciclo real y en la Etapa 9 de `PIPELINE.md`.

`make rehearse` arranca los servicios dos veces: la 1ª pasada de `--tags start` puede cambiar cosas (arrancar NGINX es un cambio legítimo) y la 2ª debe dar `changed=0`.

## Pines de apt: `make pin-check`

Requiere Internet y **no** forma parte de `preflight` (que debe funcionar offline). Lee `logrelay_nginx_version` de `roles/logrelay/defaults/main.yml` (única fuente de verdad, no duplica la versión) y comprueba con `apt-cache madison` dentro de un contenedor desechable que `nginx`, `nginx-core`, `nginx-common` y `libnginx-mod-stream` existan exactamente en esa versión; si falta alguno, falla y lista las versiones disponibles. Cada rol nuevo registra su pin en la lista del script (`local/scripts/pin-check.sh`). Para probar un defaults alternativo: `make pin-check PIN_DEFAULTS=/tmp/defaults.yml`.

## Rol common: `make common-check`

Verifica el rol `common` en las 4 VMs sobre los contenedores ya convergidos, por lo que se corre **después** de `make rehearse` (o dentro de `make preflight`, que ya lo incluye).

Qué comprueba: (1) los timers `apt-daily*` enmascarados e inactivos, (2) `99-soc-no-auto.conf` con sus 3 líneas y `apt-config dump` sin actualización automática, (3) `sshd -T` con `permitrootlogin no`, `passwordauthentication no`, `kbdinteractiveauthentication no`, `maxauthtries 3` y el puerto correcto (22222 en honeyserver), (4) que el demonio **en ejecución** solo ofrezca `publickey` (prueba que el `reload` llegó), (5) zona horaria `UTC` leída de `date +%Z`, `/etc/timezone` y el enlace de `/etc/localtime`, sin la caché de `timedatectl`.

Para que no pasen en vacío, el entorno de ensayo parte sin endurecimiento: `sshd_config.tpl` solo incluye `sshd_config.d` y los contenedores nacen en `America/Mexico_City`.

Qué NO valida: la sincronía NTP real (`NTPSynchronized`, se exige en el tag `start` solo en host real), que `apt-daily*` exista y se pueda enmascarar en la imagen de Azure, y que la unidad de sshd se llame `ssh` en la imagen real. Tampoco reproduce el `10-admin-port.conf` de cloud-init de honeyserver (aquí el puerto 22222 viene de `sshd_config`), así que el cruce entre el drop-in `10-` y el `20-` no se ejercita; y los timers de apt no estaban activos en el contenedor, así que la parada de un timer activo no se prueba.
