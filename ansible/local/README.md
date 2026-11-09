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
| `stage9-rehearse` | Etapa 9 local: pasada completa sin tags con egreso cerrado y caché de apt vencida en las 4 VMs; requiere `wazuh-rehearse` y `honeypot-rehearse` previos; **fuera** de `preflight` |
| `preflight` | todo lo anterior |
| `azure-session` / `time-guard` | `az account show` y corte de las 20:30; **fuera** de `preflight` |

## Etapa 1 — plan y autorización (sin apply)

| Target | Qué hace |
|---|---|
| `azure-session` | exige `EXPECTED_AZ_SUBSCRIPTION_NAME` (variable de entorno, nunca en el repo), `az` con sesión vigente y esa suscripción en estado `Enabled`. No imprime IDs. |
| `time-guard` | falla antes de las 07:00 y a partir de 20:30 (E1-9). Se prueba sin esperar: `TIMEGUARD_NOW=20:30 make time-guard`. |
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
- El rol `wazuh` ya instala y configura el all-in-one real, pero **no** corre en
  `preflight`: se ensaya aparte con `make wazuh-rehearse` (ver abajo).

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

## Rol wazuh: `make wazuh-rehearse` y `make wazuh-check`

El all-in-one real (Manager + Indexer + Dashboard) corre en el contenedor `wazuh`. **No** forma parte de `preflight`: descarga más de 1 GB y tarda de 10 a 25 minutos, así que el inventario local marca `wazuh_enabled: false` y el rol se omite. Úsalo cuando toques el rol y antes del primer ciclo real.

Requisitos del anfitrión (`make wazuh-hostcheck`, solo lee): `MemAvailable` suficiente, `vm.max_map_count` ≥ 262144 y disco libre. El heap del Indexer se sobrescribe a `2g` en local (el real, `8g`, no cabe en un equipo compartido).

Flujo: `make clean preflight` y luego `make wazuh-rehearse`: 1ª pasada `install,config` (exige `changed`), 2ª pasada (`changed=0`), `--check --diff`, un agente de prueba instalado en `honeyserver` y enrolado **a través del relay** (D4), egreso cerrado, `--tags start` dos veces y `make wazuh-check`. Para iterar: `make wazuh-apply TAGS=install` y `WAZUH_CHECKS="1 2" make wazuh-check`.

Los secretos del ensayo viven en `/tmp/soc-local-secrets/` (desechables, fuera del repo: así se ejerce la guarda del rol); `make clean` los borra.

Qué comprueba `wazuh-check`: (1) versión y paquetes en `hold`, (2) servicios activos, (3) puertos (1514/1515/443 abiertos; 9200 y 55000 solo en loopback; 9300, 1516, 514 y 1514/udp cerrados), (4) `ossec.conf` con los valores de D5 y `wazuh-analysisd -t`, (5) `authd.pass`, (6) heap, (7) política ISM de 30 días, (8) que el tar y el log del asistente no queden en la VM, (9) agente activo a través del relay, (10) que el gate de versión falle con una versión distinta.

Qué NO valida: UFW real y el NSG de Azure, el heap real de 8g en `Standard_B4as_v2`, el arranque en frío tras `az vm start`, que los datos del Indexer sobrevivan a `deallocate`/`start`, y el acceso al Dashboard desde la LAN por el túnel. El agente de `honeyserver` es un fixture del arnés: el rol `honeypot` lo instalará de verdad.

### Desviaciones validadas en el ensayo

- **Disco:** en contenedor, `ansible_facts.mounts` no lista el overlay `/`; el rol mide el disco libre con `df -m --output=avail /`. El mínimo sigue siendo 15000 MiB.
- **Active Response:** en `ossec.conf` 4.14.9 y 4.14.10 viene dentro de un bloque comentado. El rol lo sustituye por `<active-response><disabled>yes</disabled></active-response>` y lo valida con `wazuh-analysisd -t`.
- **`local_rules.xml`:** un `<group>` vacío lo rechaza el Manager (`Group 'group' without any rule`, CRITICAL 1220). Queda una regla base sin efecto: `id=100000`, `level=0`, `match=soc-tesis-placeholder`.
- **Check 3:** el JVM liga IPv4 en un socket dual-stack y `ss` muestra `[::ffff:127.0.0.1]:9200` y `:9300`; el clasificador acepta solo `::ffff:127.*`, no cualquier `::ffff:*`.
- **`relay-check`:** el eco en 1514/1515 del contenedor `wazuh` choca con el Manager real tras instalarlo. La sonda detiene `wazuh-manager` si está activo y lo restaura en el `trap EXIT`; sin Manager instalado nada cambia y no se relajó ninguna aserción.
- **`make` dentro de `nix-shell`:** fuera de él, el check 6 falla por falta de `ansible-inventory`, no por el rol.
- **`make wazuh-apply`** depende de `known-hosts` → `up`; `up` usa `--no-recreate`, pero conviene saberlo si hay un `wazuh` instalado y valioso.

## Rol honeypot: `make honeypot-rehearse` y `make honeypot-check`

Docker, las 7 imágenes de D2 y el Wazuh Agent reales corren dentro del contenedor `honeyserver`, con `/var/lib/docker` y `/var/lib/containerd` en volúmenes (sin overlayfs sobre overlayfs). **No** forma parte de `preflight`: el inventario local marca `honeypot_enabled: false`.

Flujo: `make clean preflight` y luego `make wazuh-rehearse` (el agente necesita el Manager). Después `make honeypot-rehearse`, que primero ejecuta `local/scripts/honeypot-reset-agent.sh`: deja `honeyserver` como una VM nueva frente al agente (sin paquete, sin `/var/ossec` y sin registrar en el Manager), para que el check 7 pruebe el enrolamiento del rol y no la clave que dejó el fixture de `wazuh-rehearse`. Ese script se niega a correr si existe `/etc/soc-tesis/honeypot-started`: el señuelo ya arrancó y hay que volver al principio con `make clean`.

Después del reset, el ensayo sigue así:
1. 1ª pasada `install,config` con el egreso abierto (exige `changed`) y el check 3 (todo dormido);
2. 2ª pasada (`changed=0`);
3. `--check --diff`;
4. egreso cerrado;
5. `--tags start` dos veces;
6. pasada completa sin tags (`changed=0`, como la Etapa 9);
7. `make honeypot-check`.

Para iterar: `make honeypot-apply TAGS=install` y `HONEYPOT_CHECKS="1 3" make honeypot-check`.

Qué comprueba `honeypot-check`:
1. paquetes en versión fijada y en `hold`, sin recomendados;
2. `RepoDigests` iguales a `.env.example`;
3. tras `install,config`, Docker, containerd y el agente inactivos y deshabilitados (lo llama `honeypot-rehearse`);
4. tras `start`, 7 contenedores `healthy`, el 22 atendido por el señuelo y sshd solo en el 22222;
5. `ossec.conf` con el relay, `client_buffer` y los `localfile` de D4;
6. `authd.pass`;
7. el agente activo en el Manager, a través del relay;
8. cada honeypot escribe un evento de prueba, y `wazuh-logcollector` lo lee: en `wazuh-logcollector.state` deben tener `events > 0` los 4 `localfile` (Cowrie, Dionaea y Tanner en JSON, y Mailoney en `journald`). El archivo lo escribe el agente en ejecución, así que sus contadores son los de la sesión actual;
9. prueba negativa: con el egreso abierto, `start` falla en la sonda.

Qué NO valida: el NSG real de Azure, el pull a través de `Allow-Out-Maintenance-Egress`, el ciclo `deallocate`/`start` con `restart: unless-stopped`, el tráfico real de Internet, ni alertas en el Manager (no hay reglas por honeypot todavía).

### Notas del ensayo

- **`~/.ssh/known_hosts` queda desfasado al recrear `honeyserver`:** la clave de host cambia. El Makefile usa `local/.known_hosts` (`ANSIBLE_USER_KNOWN_HOSTS_FILE`). Para comandos manuales, usa `-o UserKnownHostsFile=local/.known_hosts`.
- **Aviso `apt_repository` deprecado:** es conocido. El rol usa `ansible.builtin.apt_repository`; migrar a `deb822_repository` queda como mejora futura.

## Etapa 9 local: `make stage9-rehearse`

Pasada completa de `site.yml` sin `--tags` ni `--limit` sobre las 4 VMs, con el egreso cerrado y la caché de apt vencida (`/var/lib/apt/lists` con más de 2 h). Comprueba que ningún `apt` de ningún rol sale a Internet cuando no falta nada.

- **Va después de `make wazuh-rehearse` y `make honeypot-rehearse`.** Exige el Manager de Wazuh activo y `/etc/soc-tesis/honeypot-started` en `honeyserver`; si falta alguno, falla diciendo qué correr antes.
- **No está en `preflight`:** depende del Manager y de los dos rehearse previos. El objetivo en sí dura unos minutos.
- **Qué hace:** cierra el egreso, envejece la caché en las 4 VMs (`stage9-rehearse-apt-age.sh` verifica el mtime), hace dos pasadas completas que deben dar `changed=0 failed=0`, un `--check --diff` igual y los checks finales.
- **Qué NO valida:** el ciclo `deallocate`/`start` de Azure, el NSG real, el pull a través de `Allow-Out-Maintenance-Egress` ni el estado de Terraform.
