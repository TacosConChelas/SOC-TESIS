# Diseño del rol Ansible `honeypot`

**Fecha:** 2026-11-04
**Rama:** `practica/ansible-local`
**Estado:** implementado en la rama `practica/ansible-local` (plan `docs/superpowers/plans/2026-11-04-honeypot-role.md`); refinamientos en §9 (decisión E1-3 del agente durante `install`: §9.10).
**Fuentes:** `.knowledge/18_DECISIONES_IMPLEMENTACION.md` (D2, D4, D8), `.knowledge/17_SOFTWARE_BASELINE.md` (D1 §1–§2), `.knowledge/20_COMPOSE_REPRODUCIBLE.md`, ADR-006 (A6, E1-2, E1-3, E1-7, E1-8), `ansible/PIPELINE.md`, `docker-compose.yml`, `.env.example`, documentación de Wazuh (`localfile`).
**Contexto:** cuarto subproyecto de P-A1. `common`, `logrelay` y `wazuh` ya están hechos.

## 1. Objetivo

Reemplazar el rol marcador `honeypot` por la instalación real del Honey-Server (`10.50.10.10`), que comprende:
- Docker y Compose fijados a D1;
- las 7 imágenes de D2 fijadas por digest;
- el Wazuh Agent enrolado por el relay (D4).

En ningún momento puede haber un servicio del señuelo activo o habilitado mientras el egreso está abierto (E1-3).

## 2. Decisiones

| Tema | Decisión |
|---|---|
| Política del daemon (E1-3) | **Enfoque 1:** el daemon de Docker solo corre durante el pull de `install` y desde `start` en adelante. `install` no crea contenedores. |
| Enfoque 2, descartado | `compose up --no-start` crea contenedores con `restart: unless-stopped`, y un reinicio o un `docker start` accidental los levanta con el egreso abierto. |
| Enfoque 3, descartado | `docker save`/`load` desde el controlador. Evita el egreso para las imágenes, pero ningún ADR lo contempla y no ejercita el camino real del pull por digest. |
| Versión del agente | `wazuh-agent={{ wazuh_expected_version }}-1` (hoy 4.14.9-1). Un agente más nuevo que el Manager no es válido, así que se usa la misma variable que el rol `wazuh`. |
| Mailoney (D4) | **APROBADO (operador, 2026-11-04):** se queda en `journald` con filtro `CONTAINER_NAME`, sin etiqueta (ver §4.4). El plan B de D4 se descarta mientras el ensayo confirme que el decodificador JSON lee el mensaje. |
| `containerd.io` | **APROBADO (operador, 2026-11-04):** `2.3.6-1~ubuntu.22.04~jammy`. Es la versión vigente en el repo cuando se publicó `docker-ce` 29.8.2 (2.3.6-1 el 2026-09-25 y docker-ce 29.8.2 el 2026-09-30, según el listado del pool `jammy`), y cumple `containerd.io (>= 2.1.5)` del `Depends` de `docker-ce`. La rama 2.4.x (2.4.2-3, 2026-10-20) queda fuera porque es posterior al par que publicó Docker. |

**Prerrequisito:** `docker-compose.yml`, `.env.example` y `config/` tienen que estar versionados en git antes de implementar el rol. Hoy están sin seguimiento, y un rol que copia archivos no versionados no es reproducible.

## 3. Variables (prefijo `honeypot_`)

| Variable | Valor |
|---|---|
| `honeypot_docker_version` | `5:29.8.2-1~ubuntu.22.04~jammy` (para `docker-ce` **y** `docker-ce-cli`) |
| `honeypot_compose_version` | `5.6.0-1~ubuntu.22.04~jammy` |
| `honeypot_containerd_version` | `2.3.6-1~ubuntu.22.04~jammy` (§2) |
| `honeypot_docker_key_url` | `https://download.docker.com/linux/ubuntu/gpg` |
| `honeypot_docker_key_fingerprint` | `9DC858229FC7DD38854AE2D88D81803C0EBFCD88` ("Docker Release (CE deb)", RSA 4096, sin caducidad) |
| `honeypot_wazuh_key_url` | `https://packages.wazuh.com/key/GPG-KEY-WAZUH` |
| `honeypot_wazuh_key_fingerprint` | `0DCFCA5547B19D2A6099506096B3EE5F29111145` ("Wazuh.com (Wazuh Signing Key)", RSA 4096, **caduca el 2027-05-15**) |
| `honeypot_dir` | `/opt/soc-tesis` (compose, `config/`, `.env`) |
| `honeypot_data_root` | `/srv/soc-tesis` |
| `honeypot_relay_ip` | `10.50.30.10` |
| `honeypot_wait_timeout` | `300` (segundos para `--wait`) |
| `honeypot_egress_probe_urls` | `http://1.1.1.1`, `https://example.com` (fuera de Azure, E1-6) |

`wazuh_expected_version` y `wazuh_secrets_dir` pasan de `roles/wazuh/defaults` a `ansible/group_vars/all.yml`, para que los dos roles lean la misma fuente.

Centinelas en `/etc/soc-tesis/`:
- `honeypot-images`: los 7 digests ya descargados y verificados.
- `honeypot-uids.json`: el usuario de cada imagen.
- `honeypot-started`: el señuelo ya arrancó al menos una vez.

## 4. Contenido y tags

| Tag | Qué hace | Descarga |
|---|---|---|
| `install` | Repos, paquetes fijados, pull por digest, verificación de digests y descubrimiento de UIDs (§4.1–4.2) | **Sí** (único tag) |
| `config` | Directorios, archivos de compose, `ossec.conf` y `authd.pass` (§4.3–4.4) | No |
| `start` | Sonda de egreso cerrado, Docker, `compose up` y agente (§4.5) | Nunca |

### 4.1 `install`: paquetes

- Claves apt en `/usr/share/keyrings`. La clave se descarga solo si aún no está en `/etc/soc-tesis/keys/` (§9.4). En cada pasada se verifica su huella sobre la copia local con `gpg --show-keys --with-colons` (línea `fpr` de la clave primaria) contra la variable, y el rol falla si no coincide. La huella se compara completa (40 hex), nunca el ID corto.
- Repos: `download.docker.com/linux/ubuntu jammy stable` y `packages.wazuh.com/4.x/apt stable main`.
- Paquetes con `install_recommends: false` y versión exacta: `docker-ce`, `docker-ce-cli` (misma versión), `containerd.io`, `docker-compose-plugin` y `wazuh-agent`. `docker-buildx-plugin` y `docker-ce-rootless-extras` no se instalan.
- `apt-mark hold` sobre los cinco.
- El `policy-rc.d` de `common` impide que el postinst arranque servicios, pero no evita que los habilite. Por eso, **solo si no existe `honeypot-started`**, se aplica `enabled: false, state: stopped` a `docker.service`, `docker.socket`, `containerd.service` y `wazuh-agent`.

### 4.2 `install`: imágenes (bloque condicionado)

El bloque se **salta** si `honeypot-images` coincide con los 7 digests de `.env.example`. Así la 2ª pasada da `changed=0` y no toca el daemon en producción.

Si no coincide, se ejecuta como `block`/`always`:
1. **block:**
   1. arrancar `docker.service` (sin habilitarlo);
   2. `community.docker.docker_compose_v2_pull` sobre `honeypot_dir`;
   3. comparar `RepoDigests` de cada imagen con `.env.example` (paso 5 del baseline); el rol falla si alguna difiere;
   4. leer `Config.User` de cowrie, dionaea y tanner con `docker image inspect`, resolverlo a UID:GID numérico y guardarlo en `honeypot-uids.json`;
   5. escribir `honeypot-images`.
2. **always** (solo si no existe `honeypot-started`): detener y deshabilitar `docker.service`, `docker.socket` y `containerd.service`. Un pull fallido no deja el daemon vivo.

Si cambian los digests en producción (`honeypot-started` existe), el bloque se ejecuta sin detener nada. Con el egreso cerrado, el pull falla con un mensaje que pide abrir la ventana de mantenimiento.

**Precisión sobre E1-3:** el daemon sí corre durante el pull con el egreso abierto. Es aceptable porque no hay contenedores ni servicio del señuelo. Lo que E1-3 prohíbe es el señuelo activo o habilitado, no el daemon durante la descarga.

### 4.3 `config`: archivos del host

- Directorios `{{ honeypot_data_root }}/{cowrie/log,dionaea/lib,tanner/log}`, con dueño tomado de `honeypot-uids.json`. Los UIDs se descubrieron en `install` porque aquí el daemon está apagado. El rol falla si el archivo no existe.
- Copia a `honeypot_dir` de `docker-compose.yml`, `config/` y `.env.example` (como `.env`) desde la raíz del repo.
- No hay handlers que arranquen nada durante la ventana: los handlers de reinicio (`wazuh-agent`) llevan `when: honeypot-started existe`. En producción, un cambio de `config` se aplica con `--tags config,start`.

### 4.4 `config`: Wazuh Agent

`ossec.conf` del agente:
- `<server><address>{{ honeypot_relay_ip }}</address>` y enrolamiento con contraseña;
- `<client_buffer>` con `queue_size` 100000 y `events_per_second` 500 (dentro de los límites de Wazuh);
- los `localfile` de D4:

| Honeypot | location | log_format | Etiqueta |
|---|---|---|---|
| Cowrie | `/srv/soc-tesis/cowrie/log/cowrie.json` | `json` | `<label key="@honeypot">cowrie</label>` |
| Dionaea | `/srv/soc-tesis/dionaea/lib/dionaea.json` | `json` | `<label key="@honeypot">dionaea</label>` |
| Snare/Tanner | `/srv/soc-tesis/tanner/log/tanner_report.json` | `json` | `<label key="@honeypot">tanner</label>` |
| Mailoney | `journald` + `<filter field="CONTAINER_NAME">^soc-tesis-mailoney$</filter>` | `journald` | **ninguna** |

- Todos con `<only-future-events>no</only-future-events>` (aplica a archivos, según la documentación de `localfile`).
- La clave lleva el prefijo `@` porque Wazuh descarta la etiqueta si la clave ya existe en el evento.
- `<label>` solo funciona con `log_format json`. Mailoney se distingue por `CONTAINER_NAME` en las reglas. Si el operador elige el plan B de D4 (stdout a un archivo del bind), pasa a `json` con etiqueta y se agrega un cuarto directorio.

`authd.pass`: el mismo patrón que el rol `wazuh`. Se lee de `wazuh_secrets_dir` en el controlador (el rol falla si no existe o si está dentro del repo) y se entrega en `/var/ossec/etc/authd.pass` con `640 root:wazuh` y `no_log`.

### 4.5 `start`

1. **Sonda de egreso cerrado** (E1-3 dentro del rol, además del gate del pipeline): cada URL de `honeypot_egress_probe_urls` debe fallar con `curl -m5`. Si alguna responde, el rol se detiene sin arrancar nada.
2. `docker.socket`, `docker.service` y `containerd.service`: `enabled: true, state: started`.
3. `community.docker.docker_compose_v2` con `project_src: honeypot_dir`, `state: present`, `pull: never`, `build: never`, `wait: true` y `wait_timeout: honeypot_wait_timeout`. Con `pull: never`, una imagen faltante hace fallar el rol en lugar de colgarlo intentando descargar. El módulo da `changed=0` cuando no hay cambios.
4. `wazuh-agent`: `enabled: true, state: started`. Luego se espera, con reintentos, a que `/var/ossec/var/run/wazuh-agentd.state` muestre `status='connected'`. El primer arranque se enrola por el relay.
5. Escribir `honeypot-started`.

## 5. Errores y casos límite

| Riesgo | Comportamiento |
|---|---|
| Pull fallido o digest distinto | `always` detiene y deshabilita Docker. El rol falla y no escribe `honeypot-images`. |
| 2ª pasada completa con el egreso cerrado (Etapa 9) | `install` se salta el bloque de imágenes y no toca servicios (existe `honeypot-started`): `changed=0`. |
| Imagen faltante en `start` | `pull: never` hace fallar de inmediato con el nombre de la imagen. |
| Healthcheck roto (pendiente E3: `python3` en el `PATH` de las imágenes) | `wait_timeout` corta la espera y el rol informa qué servicio no quedó sano. |
| Egreso todavía abierto en `start` | La sonda falla y no arranca nada. |
| `honeypot-uids.json` ausente en `config` | Falla con un mensaje que pide correr `install`. |
| Relay o Manager caídos en el primer arranque del agente | Reintentos acotados. Si se agotan, falla indicando que la cadena D4 no está arriba. |
| Log rotado con el agente detenido | Con `only-future-events=no`, Wazuh relee desde el inicio. Los duplicados se miden en TEST-008 (D4). |

## 6. Pruebas locales

- **Arnés:** `make honeypot-rehearse`, aparte del `preflight` (mismo patrón que `wazuh-rehearse`).
  1. 1ª pasada `--tags install,config` con egreso; exige `changed` y ningún servicio del señuelo activo ni habilitado.
  2. 2ª pasada: `changed=0`.
  3. `--check --diff` sin cambios.
  4. Cerrar el egreso (red `internal`).
  5. `--tags start` dos veces.
  6. Pasada completa sin tags: `changed=0` y el señuelo sigue arriba.
  7. `make honeypot-check`.
- **Docker dentro del contenedor systemd:** puede fallar con overlayfs sobre overlayfs (Docker 29 usa el snapshotter de containerd). Si falla, el inventario local fija el driver `vfs` en `/etc/docker/daemon.json`, y la diferencia se anota en §9.

**`make honeypot-check`** (exit ≠ 0 si algo falla):

| # | Check |
|---|---|
| 1 | Los 5 paquetes en la versión de las variables y en `hold`; `docker-buildx-plugin` y `rootless-extras` ausentes |
| 2 | `RepoDigests` de las 7 imágenes iguales a `.env.example` |
| 3 | Tras `install,config`: docker, socket, containerd, agente y contenedores inactivos **y** deshabilitados |
| 4 | Tras `start`: 7 contenedores `healthy`; el 22 lo atiende Cowrie (banner distinto de OpenSSH del host) y sshd sigue en el 22222 |
| 5 | `ossec.conf` con el relay, `client_buffer`, los 4 `localfile` y las etiquetas `@honeypot` en los tres JSON |
| 6 | `authd.pass` en `640 root:wazuh` con el mismo `sha256` que el del controlador, sin imprimirlo |
| 7 | El agente aparece activo en `agent_control -l` del Manager |
| 8 | Un login fallido contra Cowrie aparece en `alerts.json` del Manager con `@honeypot: cowrie` |
| 9 | Prueba negativa: con el egreso abierto, `start` falla en la sonda y no arranca nada |

**No se valida en local:** el NSG real de Azure; el pull desde Docker Hub/GHCR a través de `Allow-Out-Maintenance-Egress`; el ciclo `deallocate`/`start` con `restart: unless-stopped`; el tráfico real de Internet al señuelo.

## 7. Criterio de listo

- `make honeypot-rehearse` pasa los 9 checks, con la 2ª pasada y la pasada completa en `changed=0`.
- `make preflight` sigue en verde.
- Lint, contrato de tags (`--list-tasks --tags start` sin módulos de descarga) y escaneo de secretos limpios.
- El comentario de `roles/honeypot/tasks/main.yml` ("este rol no tiene tareas `install`") se reemplaza.
- `PIPELINE.md` (Etapas 6 y 8) se actualiza con la sonda de egreso y la espera del agente.

**Dependencias:**
- Compose, `.env.example` y `config/` versionados (§2).
- `pin-check` ampliado (parte de la implementación): lee directamente el índice `download.docker.com/linux/ubuntu/dists/jammy/stable/binary-amd64/Packages`, igual que ya hace con el de Wazuh y sin configurar el repo en el contenedor. Exige que `docker-ce`, `docker-ce-cli`, `containerd.io` y `docker-compose-plugin` existan en la versión de los `defaults` del rol y que `wazuh-agent` tenga `${wazuh_expected_version}-1`. También avisa si la clave de Wazuh caduca en menos de 60 días.
- Baseline `17_SOFTWARE_BASELINE.md` actualizado a `wazuh-agent` 4.14.9-1 (Linux y MSI de Windows), a cargo del operador. Ya está comprobado que `4.14.9-1` existe en `packages.wazuh.com/4.x/apt` para agent, manager, indexer y dashboard (índice consultado el 2026-11-04).
- `community.docker` en `requirements.yml` para el controlador real.

## 8. Fuera de alcance

- Reglas y decodificadores por honeypot en `local_rules.xml` (otra fase).
- Plan B de Mailoney (descartado, §2).
- Verificación E3 de los healthchecks contra las imágenes (se registra como resultado del ensayo).
- Agentes del laboratorio (Windows 11, Ubuntu).

## 9. Refinamientos del plan de implementación (2026-11-04)

Cada punto se comprobó contra el código del rol. Donde el texto previo no coincidía con el código, se reescribe aquí. Los textos §4.2 (paso 4, lectura de `Config.User`) y §6 (check 8, login en `alerts.json`) quedan superados por §9.3 y §9.5.

1. **`honeypot_enabled`:** por defecto `true` en `roles/honeypot/defaults/main.yml`, y `false` en `local/inventory.yml`, para que `preflight` no instale Docker, igual que `wazuh_enabled`. `make honeypot-rehearse` lo activa con `-e honeypot_enabled=true`.

2. **Docker dentro del contenedor:** `/var/lib/docker` y `/var/lib/containerd` van en volúmenes del servicio `honeyserver` (`local/docker-compose.yml`), no en el driver `vfs` de §6, para no apilar overlayfs sobre overlayfs. El driver `vfs` no fue necesario y no aparece en el repo.

3. **UID de las imágenes (corrige el texto previo):** el descubrimiento de `install` (`roles/honeypot/tasks/main.yml:246`) ejecuta `docker run --rm --network none --entrypoint python3 <imagen> -c 'import os; …'`. Es un contenedor efímero y sin red, no un servicio del señuelo. Devuelve el UID con el que corre el **entrypoint** (el usuario por defecto de la imagen, `Config.User`), no el del proceso que escribe. Coincide en cowrie (999) y tanner (2000). No coincide en Dionaea: `Config.User` está vacío, el entrypoint corre como root, hace `chown` y baja a 1000. `honeypot-uids.json` guarda `dionaea/lib: ["0","0"]`.
   - **Resolución aplicada:** `honeypot_bind_dirs` admite `owner: ["1000","1000"]` en la entrada de `dionaea/lib`. Las tareas de directorios (`:302`) y de JSON vacíos (`:318`) usan `item.owner | default(<valor de honeypot-uids.json>)`. Una sola fuente por entrada, sin ramas por nombre de honeypot. El descubrimiento y `honeypot-uids.json` no cambian.
   - **Deuda:** la causa sigue en el descubrimiento. No hay control automático que avise si cambia el usuario de proceso de una imagen al subirla.

4. **`apt` en la Etapa 9 (corrige el texto previo):** el rol no hace `apt` con red en cada pasada.
   - Claves: `stat` de `/etc/soc-tesis/keys/<nombre>.asc` (`:58`); `get_url` solo si el archivo no existe (`:67`). Con el archivo presente no hay petición de red.
   - Huella: `gpg --show-keys` sobre la copia local, en cada pasada, sin red. Si no coincide, el `assert` falla igual que antes.
   - Repos: `apt_repository` con `update_cache: false` (`:119`).
   - Paquetes: `apt` con `update_cache: true` (`:143`), pero solo se ejecuta si cambió un repo o si falta un paquete en su versión exacta (`:145`, comparando con `dpkg-query`).
   - Con el egreso cerrado y el sistema ya convergido, la pasada completa no refresca la caché. Lo confirma el ensayo: `changed=0` y `failed=0` en la pasada completa sin tags.

5. **Check 8 (corrige el texto previo):** no hay reglas por honeypot (§8), así que nada llega a `alerts.json`. `honeypot-check.sh` genera un evento de prueba en cada honeypot (SSH, FTP, HTTP y SMTP desde el contenedor atacante) y comprueba que `wazuh-logcollector` lo lee: en `/var/ossec/var/run/wazuh-logcollector.state`, los 4 `localfile` (Cowrie, Dionaea y Tanner en JSON, y Mailoney en `journald`) deben tener `events > 0`. El contador es de la sesión del agente en ejecución. El transporte hasta el Manager lo cubre el check 7 (agente activo a través del relay).

6. **`journald` (corrige el texto previo):** el paquete `wazuh-agent` 4.14.9 trae un `localfile` de `journald` sin filtro, que mandaría el journal del sistema al Manager. El rol lo **elimina** con una tarea `replace` (`roles/honeypot/tasks/main.yml:355`) y declara el de Mailoney con filtro `CONTAINER_NAME` (`:363`). La verificación (`:402`) exige exactamente un `<location>journald</location>`. Motivo: minimización de datos (doc 19 §7). Si el paquete cambia la forma del bloque, la eliminación no coincide y la verificación falla con un mensaje que lo explica; no se relaja la aserción.

7. **Fixture de `wazuh-rehearse`:** usa `wazuh.asc` y `wazuh.list` iguales a los del rol (`local/scripts/wazuh-agent-fixture.sh`), para que `apt` no vea dos `Signed-By`. Antes de `honeypot-rehearse`, `local/scripts/honeypot-reset-agent.sh` quita el agente del fixture. Purga con `--allow-change-held-packages` (`:41`), porque el rol deja `wazuh-agent` en `hold`. En el ensayo de honeypot no había agente que purgar y el script terminó con `ok`.

8. **Ubicación de `wazuh_expected_version` y `wazuh_secrets_dir`:** viven en `ansible/group_vars/all.yml`. La ruta `inventory/group_vars/all.yml` de §3 estaba mal y se corrigió.

9. **Los `localfile` de D4 deben existir antes de arrancar el agente.** logcollector los abre al arrancar y no reintenta. Un archivo ausente no se ingiere, y su primer evento se pierde incluso tras reiniciar el agente. Medido en el laboratorio local: con Tanner sin archivo al arrancar, `events=0` y offset 499 (el final del archivo); con el archivo presente al arrancar, un evento nuevo se contó en menos de 80 s. El mecanismo interno exacto no está confirmado; la evidencia es empírica.
   - El rol crea los tres JSON vacíos en `config` (`:318`): `copy` con `content: ""`, `force: false`, modo `0644` y el dueño de cada imagen. Con `force: false` nunca pisa un archivo con eventos, y en las pasadas siguientes la tarea da `ok`.
   - En Azure es el mismo caso: Tanner crea su archivo con el primer ataque, que puede llegar horas después del arranque del agente.
   - **Restricción de D4:** los `localfile` deben existir antes de arrancar el agente.

10. **El agente durante `install` y E1-3: decidido.** Lo que hace el código:
    - `install` no arranca el agente. El `policy-rc.d` de `common` devuelve 101 al postinst (`roles/common/tasks/main.yml:43-50`, `exit 101` en la 49), y el handler `Reiniciar wazuh-agent` solo actúa si existe `honeypot-started` (`roles/honeypot/handlers/main.yml`). En la primera pasada del ensayo el handler se saltó.
    - `install` para y deshabilita `wazuh-agent` solo si no existe `honeypot-started` (tarea «Dejar Docker y el agente detenidos y deshabilitados», `roles/honeypot/tasks/main.yml:157-165`). En el ensayo esa tarea dio `ok`: el agente ya estaba parado y deshabilitado tras el postinst.
    - **Decisión:** el agente cuenta como servicio del honeypot. E1-3 se garantiza durante `install` con el `policy-rc.d` de `common` (el postinst no arranca nada) y al final de `install` con la tarea que lo detiene y deshabilita, más el check 3. Un `enabled` transitorio dejado por el postinst no expone nada, porque no hay proceso. No hace falta un guard antes del `apt install`: un agente que no arrancó no recibe tráfico, y un guard solo cubriría una ventana de segundos sin proceso.
    - **Riesgo aceptado:** un postinst futuro que ignorara `policy-rc.d` y arrancara el agente solo lo detectaría el check 3 al final de `install`, no en el intervalo. Lo cubren `pin-check` y el gate de versión.

11. **Tiempos reales del ensayo** (para recalibrar estimaciones): `make clean preflight` 2 min 44 s (21:14:34 a 21:17:18); `make wazuh-rehearse` 8 min 05 s (21:17:18 a 21:25:23); `make honeypot-rehearse` 5 min 07 s (21:25:23 a 21:30:30).

12. **Inventario:** `ansible.cfg` apunta por defecto a `inventory/hosts.yml`, con las IPs `10.50.x` del entorno Azure, que comparte el lab local. En pruebas, nunca `ansible-playbook` sin `ANSIBLE_INVENTORY=local/inventory.yml`. El Makefile lo exporta; los comandos manuales deben fijarlo.

13. **Resuelto en `dc0a90b` (`common`), `fa4fe34` (`strongswan`) y `ae7c35d` (`logrelay`):** los tres roles instalaban con `update_cache: true` y `cache_valid_time: 3600`, y con el egreso cerrado y la caché vencida la pasada completa fallaba. Ahora cada uno solo refresca la caché si falta un paquete base (o, en `logrelay`, si NGINX no está en la versión fijada). Verificado con la caché envejecida: rojo antes del arreglo, verde después.
