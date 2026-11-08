# Rol `honeypot` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reemplazar el rol marcador `honeypot` por la instalación real del Honey-Server: Docker y Compose fijados (D1), las 7 imágenes por digest (D2) y el Wazuh Agent enrolado por el relay (D4), sin ningún servicio del señuelo activo ni habilitado mientras el egreso está abierto (E1-3).

**Architecture:** `install` agrega los repos (con la huella de cada clave verificada), instala los paquetes en versión exacta y en `hold`, y deja Docker y el agente detenidos y deshabilitados. Un bloque condicionado por un centinela arranca Docker solo para el pull, verifica los digests, descubre el UID de las imágenes y lo vuelve a dormir. `config` crea los directorios del bind, copia el proyecto compose, edita `ossec.conf` y entrega `authd.pass`, todo sin arrancar nada. `start` exige el egreso cerrado, levanta Docker, hace `compose up` sin descargar y espera al agente conectado. El ensayo local corre Docker dentro del contenedor `honeyserver`, con un target aparte para no alargar el `preflight`.

**Tech Stack:** Ansible (ansible-core 2.21, `community.general` 12.6.1, `community.docker` 5.2.0), Docker Engine 29.8.2 + Compose 5.6.0, Wazuh Agent 4.14.9, Ubuntu 22.04 (contenedor systemd), bash, Python 3 (stdlib + PyYAML del nix-shell), GNU make.

**Spec:** `docs/superpowers/specs/2026-11-04-honeypot-role-design.md`.

## Global Constraints

- Rama `practica/ansible-local`. Todo comando se corre desde `/home/tacosconchelas/Projects/SOC-TESIS/ansible` dentro de `nix-shell --run '...'` (o en un `nix-shell` abierto).
- Contrato de tags (E1-8): `install` es el único que descarga; `config` no descarga ni arranca; `start` **nunca** descarga. **Cada tarea lleva sus propios tags**, también las anidadas en `block`/`always`, porque `tags-contract.py` los exige tarea por tarea.
- E1-3: con el egreso abierto no queda activo ni habilitado `docker.service`, `docker.socket`, `containerd.service`, `wazuh-agent` ni ningún contenedor. El daemon solo corre durante el pull de `install`.
- Versiones exactas (D1): `docker-ce` y `docker-ce-cli` = `5:29.8.2-1~ubuntu.22.04~jammy`; `containerd.io` = `2.3.6-1~ubuntu.22.04~jammy`; `docker-compose-plugin` = `5.6.0-1~ubuntu.22.04~jammy`; `wazuh-agent` = `{{ wazuh_expected_version }}-1` (hoy `4.14.9-1`). `install_recommends: false`; `docker-buildx-plugin` y `docker-ce-rootless-extras` **no** se instalan.
- Huellas de las claves apt (40 hex, clave primaria): Docker `9DC858229FC7DD38854AE2D88D81803C0EBFCD88`; Wazuh `0DCFCA5547B19D2A6099506096B3EE5F29111145` (caduca el 2027-05-15).
- Repos: `deb [arch=amd64 signed-by=/usr/share/keyrings/docker.asc] https://download.docker.com/linux/ubuntu jammy stable` y `deb [signed-by=/usr/share/keyrings/wazuh.asc] https://packages.wazuh.com/4.x/apt/ stable main`.
- Las 7 imágenes salen **solo** de las líneas `*_IMAGE=` de `.env.example` en la raíz del repo. No se copian digests a ningún otro archivo.
- D4: relay `10.50.30.10`; `client_buffer` con `queue_size` 100000 y `events_per_second` 500; `localfile` de Cowrie, Dionaea y Tanner con `log_format json`, `only-future-events no` y `<label key="@honeypot">`; Mailoney por `journald` con `<filter field="CONTAINER_NAME">^soc-tesis-mailoney$</filter>`, **sin** etiqueta (decisión del operador, 2026-11-04).
- Secretos: `authd.pass` sale de `wazuh_secrets_dir` en el controlador, que debe estar **fuera** del repo (el rol falla si no). Toda tarea que lo toque lleva `no_log: true`. En el ensayo local vive en `/tmp/soc-local-secrets/`.
- Variables con prefijo `honeypot_` (regla `var-naming[no-role-prefix]` de `ansible-lint`), incluidas las de `register`. Se usan sin prefijo propio solo `wazuh_expected_version` y `wazuh_secrets_dir`, que viven en `ansible/group_vars/all.yml`.
- Los cambios se limitan a `ansible/`, `docs/` y a versionar `docker-compose.yml`, `.env.example` y `config/` (Tarea 1). No tocar `terraform/` ni `.knowledge/`. La única dependencia nueva es la colección `community.docker` en `requirements.yml` (ya viene en el nix-shell).
- Gates por código de salida, nunca por texto en stdout. Mensajes en español.
- Commits en español, sin líneas de atribución.
- No debilitar ningún check ni regla de lint para lograr verde. Si un check parece mal escrito, o Docker, las imágenes o el agente reales se comportan distinto a lo supuesto en este plan (formato de `wazuh-logcollector.state`, `python3` ausente en una imagen, un `localfile` de `journald` que ya trae el paquete, overlayfs dentro del contenedor), **detenerse y reportar con evidencia**.
- `make clean preflight` tarda más de 10 minutos, `make wazuh-rehearse` de 10 a 25 y `make honeypot-rehearse` otros 10 a 20 (descarga ~2 GB de imágenes). Correrlos **en segundo plano con la salida a un archivo** y esperar a que terminen. No lanzar dos a la vez.

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `docker-compose.yml`, `.env.example`, `config/` (raíz, ahora versionados) | Proyecto compose del Honey-Server (D2/D3), fuente del rol |
| `ansible/group_vars/all.yml` (nuevo) | `wazuh_expected_version` y `wazuh_secrets_dir`, compartidas por los roles `wazuh` y `honeypot` |
| `ansible/roles/wazuh/defaults/main.yml` (mod) | Pierde esas dos variables |
| `ansible/local/scripts/wazuh-check.sh`, `wazuh-agent-fixture.sh`, `pin-check.sh` (mod) | Leen la versión desde `group_vars/all.yml`. El fixture deja la clave y el repo de Wazuh con los mismos nombres que el rol |
| `ansible/local/scripts/tags-contract.py` (mod) | `docker_compose_v2_pull` cuenta como descarga; `docker_compose_v2` en `start` exige `pull: never`; `--selftest` |
| `ansible/local/docker-compose.yml` (mod) | Volúmenes para `/var/lib/docker` y `/var/lib/containerd` de `honeyserver` |
| `ansible/local/inventory.yml` (mod) | `honeypot_enabled: false` y `wazuh_secrets_dir` en `honeyserver` |
| `ansible/local/scripts/honeypot-conf-check.py` (nuevo) | Valida el `ossec.conf` del agente (check 5) |
| `ansible/local/scripts/honeypot-check.sh` (nuevo) | Los 9 checks de la spec §6 (subconjunto con `HONEYPOT_CHECKS`) |
| `ansible/Makefile` (mod) | Targets `honeypot-apply`, `honeypot-rehearse` y `honeypot-check`; `tags-contract` corre el selftest |
| `ansible/requirements.yml` (mod) | `community.docker` 5.2.0 para el controlador real |
| `ansible/roles/honeypot/defaults/main.yml` (nuevo) | Variables `honeypot_*` |
| `ansible/roles/honeypot/handlers/main.yml` (nuevo) | Reinicio del agente, solo si el señuelo ya arrancó |
| `ansible/roles/honeypot/tasks/main.yml` (reemplaza) | Tareas `install`, `config` y `start` |
| `ansible/PIPELINE.md`, `ansible/local/README.md`, spec (mod) | Documentación y refinamientos |

**Refinamientos de la spec que introduce este plan (se registran en la Tarea 8):**
1. `honeypot_enabled` (por defecto `true`; `false` en el inventario local) para que `preflight` no instale Docker, igual que `wazuh_enabled`.
2. Docker dentro del contenedor usa **volúmenes** para `/var/lib/docker` y `/var/lib/containerd`, no el driver `vfs`: así no se apila overlayfs sobre overlayfs y se prueba el mismo snapshotter que en Azure.
3. El UID de cada imagen se lee con un contenedor efímero `docker run --rm --network none --entrypoint python3 …`. Es transitorio y sin red, no un servicio del señuelo.
4. `apt` solo refresca la caché si cambió un repo o falta un paquete en su versión. Así la pasada completa con el egreso cerrado (Etapa 9) no intenta `apt-get update`.
5. El check 8 ya no busca una alerta en `alerts.json`: sin reglas por honeypot (fuera de alcance) no hay alerta. En su lugar comprueba que cada honeypot escribe su evento y que `wazuh-logcollector` lo leyó. El transporte hasta el Manager ya lo prueba el check 7.
6. El rol exige **un solo** `localfile` de `journald` en `ossec.conf`. Si el paquete trae uno propio, el rol falla y se decide aparte.
7. El fixture de `wazuh-rehearse` deja la clave y el repo de Wazuh con los mismos nombres y contenido que el rol, para que `apt` no vea dos `Signed-By` distintos para el mismo repo.

**Orden:** las Tareas 1, 2 y 3 son independientes entre sí. La 4 depende de la 2. Las 5, 6 y 7 son secuenciales y dependen de la 4. La 8 va al final. Si `git` reporta `index.lock`, esperar unos segundos y reintentar.

---

### Task 1: Versionar el proyecto compose del Honey-Server

**Files:**
- Add to git: `docker-compose.yml`, `.env.example`, `config/` (raíz del repo, hoy sin seguimiento)

**Interfaces:**
- Produces: `docker-compose.yml`, `.env.example` (con 7 líneas `*_IMAGE=`) y `config/{dionaea,tanner}/…` versionados, que el rol copia desde `{{ playbook_dir }}/..`.

- [ ] **Step 1: Revisar que no contengan secretos**

Run (desde la raíz del repo):
```bash
cd /home/tacosconchelas/Projects/SOC-TESIS
git status --short docker-compose.yml .env.example config/
find config -type f | sort
grep -nEi 'pass(word)?|secret|token|BEGIN .*PRIVATE' docker-compose.yml .env.example $(find config -type f) || echo "sin coincidencias"
```
Expected: los tres aparecen como `??`; la lista de `config/` muestra solo `dionaea/dionaea.cfg`, `dionaea/ihandlers-enabled/*`, `dionaea/services-enabled/*` y `tanner/config.yaml`. El `grep` da `sin coincidencias`, o solo comentarios del tipo "No guardar credenciales". Si aparece un valor real, **detenerse y reportar**.

- [ ] **Step 2: Agregarlos y correr el escaneo de secretos sobre el árbol de git**

```bash
git add docker-compose.yml .env.example config/
nix-shell ansible/shell.nix --run 'python3 ansible/local/scripts/secret-scan.py'
```
Expected: `secret-scan` termina con exit 0.

- [ ] **Step 3: Validar el compose con las variables de `.env.example`**

```bash
cp .env.example /tmp/soc-env-check && docker compose --env-file /tmp/soc-env-check -f docker-compose.yml config -q && echo compose-ok; rm -f /tmp/soc-env-check
```
Expected: `compose-ok`.

- [ ] **Step 4: Commit**

```bash
git commit -m "chore: versionar el proyecto compose del Honey-Server" -m "docker-compose.yml, .env.example (7 digests de D2) y config/ de Dionaea y Tanner. El rol honeypot los copia desde el repo; sin versionar no era reproducible."
```

---

### Task 2: Variables compartidas en `group_vars/all.yml`

**Files:**
- Create: `ansible/group_vars/all.yml`
- Modify: `ansible/roles/wazuh/defaults/main.yml`, `ansible/local/inventory.yml`, `ansible/local/scripts/wazuh-check.sh`, `ansible/local/scripts/wazuh-agent-fixture.sh`, `ansible/local/scripts/pin-check.sh`

**Interfaces:**
- Produces: `wazuh_expected_version` (cadena `"4.14.9"`, formato exacto `wazuh_expected_version: "X.Y.Z"` en la primera columna, porque lo leen scripts con `sed`) y `wazuh_secrets_dir`, visibles en todos los hosts del playbook `site.yml`.
- Precedencia que se aprovecha: las variables de host del inventario local (`wazuh_secrets_dir: /tmp/soc-local-secrets`) ganan sobre `group_vars/all.yml` del playbook.

- [ ] **Step 1: Escribir la sonda de variables (prueba en rojo)**

Crear `ansible/.vars-probe.yml` (temporal, se borra en el Step 6):
```yaml
- name: Sonda de variables compartidas
  hosts: wazuh,honeyserver
  gather_facts: false
  tasks:
    - name: Exigir las variables compartidas en ambos hosts
      ansible.builtin.assert:
        that:
          - wazuh_expected_version == "4.14.9"
          - wazuh_secrets_dir == "/tmp/soc-local-secrets"
```

- [ ] **Step 2: Correrla y ver que falla**

Run: `nix-shell --run 'ANSIBLE_CONFIG=local/ansible.cfg ansible-playbook -i local/inventory.yml .vars-probe.yml'`
Expected: FALLA en `honeyserver` (`wazuh_expected_version` no definida, porque vive en los `defaults` del rol `wazuh`).

- [ ] **Step 3: Crear `ansible/group_vars/all.yml`**

```yaml
---
# Variables compartidas por varios roles (spec 2026-11-04-honeypot-role-design.md §3).
# Baseline D1. El asistente de Wazuh instala el ultimo parche 4.14.x: si difiere, el gate
# del rol wazuh falla. El agente del honeyserver usa la misma version: un agente mas
# nuevo que el Manager no es valido. Formato exacto: lo leen scripts con sed.
wazuh_expected_version: "4.14.9"
# Directorio de secretos en el CONTROLADOR; debe quedar fuera del repositorio.
wazuh_secrets_dir: "~/soc-tesis-secrets/wazuh"
```

- [ ] **Step 4: Quitar las dos variables de `roles/wazuh/defaults/main.yml`**

Borrar exactamente estas cuatro líneas, con sus comentarios:
```yaml
# Baseline D1. El asistente instala el ultimo parche 4.14.x: si difiere, el gate falla.
wazuh_expected_version: "4.14.9"
```
```yaml
# Directorio de secretos en el CONTROLADOR; debe quedar fuera del repositorio.
wazuh_secrets_dir: "~/soc-tesis-secrets/wazuh"
```
En su lugar, debajo de `wazuh_enabled: true`, agregar una línea:
```yaml
# wazuh_expected_version y wazuh_secrets_dir viven en group_vars/all.yml (los usa tambien el rol honeypot).
```
`wazuh_secrets_dir_real` se queda en este archivo: sigue resolviendo `wazuh_secrets_dir`.

En `ansible/local/inventory.yml`, el host `honeyserver` queda así (la línea de `honeypot_enabled` se agrega en la Tarea 4):
```yaml
        honeyserver:
          ansible_host: 10.50.10.10
          ansible_port: 22222
          wazuh_secrets_dir: /tmp/soc-local-secrets # authd.pass del ensayo (fuera del repo)
```

- [ ] **Step 5: Apuntar los tres scripts a `group_vars/all.yml`**

`ansible/local/scripts/wazuh-agent-fixture.sh`: reemplazar
```bash
defaults="$here/../../roles/wazuh/defaults/main.yml"
```
por
```bash
defaults="$here/../../group_vars/all.yml"
```

`ansible/local/scripts/wazuh-check.sh`: debajo de la línea `defaults="$ansible_dir/roles/wazuh/defaults/main.yml"` agregar
```bash
shared="$ansible_dir/group_vars/all.yml"
```
y reemplazar
```bash
want_version="$(default_of wazuh_expected_version)"
[ -n "$want_version" ] || { echo "FALLA: wazuh_expected_version no esta en $defaults" >&2; exit 1; }
```
por
```bash
want_version="$(sed -n 's/^wazuh_expected_version:[[:space:]]*"\([^"]*\)".*/\1/p' "$shared" | head -n1)"
[ -n "$want_version" ] || { echo "FALLA: wazuh_expected_version no esta en $shared" >&2; exit 1; }
```

`ansible/local/scripts/pin-check.sh`: reemplazar
```bash
wazuh_defaults="${PIN_CHECK_WAZUH_DEFAULTS:-$root/roles/wazuh/defaults/main.yml}"
```
por
```bash
wazuh_defaults="${PIN_CHECK_WAZUH_DEFAULTS:-$root/group_vars/all.yml}"
```
y en ese mismo bloque cambiar los dos textos que nombran el archivo:
- `echo "aviso: roles/wazuh/defaults/main.yml no existe todavia; se omite la comprobacion del indice de Wazuh"` → `echo "aviso: group_vars/all.yml no existe todavia; se omite la comprobacion del indice de Wazuh"`
- `echo "  decide si el baseline sube y actualiza wazuh_expected_version en roles/wazuh/defaults/main.yml" >&2` → `echo "  decide si el baseline sube y actualiza wazuh_expected_version en group_vars/all.yml" >&2`

- [ ] **Step 6: Verificar y borrar la sonda**

```bash
nix-shell --run 'ANSIBLE_CONFIG=local/ansible.cfg ansible-playbook -i local/inventory.yml .vars-probe.yml' && rm .vars-probe.yml
nix-shell --run 'bash -n local/scripts/wazuh-check.sh local/scripts/wazuh-agent-fixture.sh local/scripts/pin-check.sh && make lint tags-contract'
nix-shell --run 'make pin-check'
grep -rn "roles/wazuh/defaults/main.yml" local/scripts/wazuh-agent-fixture.sh local/scripts/pin-check.sh || echo "sin referencias viejas"
```
Expected: la sonda pasa en `wazuh` y `honeyserver` (`failed=0`); lint y `tags-contract` en verde; `pin-check: ok` (requiere Internet), incluida la línea `ok: el asistente de Wazuh instalaria 4.14.9`; `sin referencias viejas`. `wazuh-check.sh` sí sigue nombrando `roles/wazuh/defaults/main.yml` para `heap` y `retention`, y eso es correcto.

- [ ] **Step 7: Commit**

```bash
git add group_vars/all.yml roles/wazuh/defaults/main.yml local/inventory.yml local/scripts/wazuh-check.sh local/scripts/wazuh-agent-fixture.sh local/scripts/pin-check.sh
git commit -m "refactor(ansible): wazuh_expected_version y wazuh_secrets_dir a group_vars/all.yml" -m "Los usan los roles wazuh y honeypot (spec honeypot §3). Los scripts del arnés leen la versión desde la nueva ubicación."
```

---

### Task 3: El contrato de tags reconoce Compose

**Files:**
- Modify: `ansible/local/scripts/tags-contract.py`, `ansible/Makefile` (target `tags-contract`)

**Interfaces:**
- Produces: `tags-contract.py --selftest` (exit 0 si las reglas detectan los casos sintéticos). Regla nueva: en `start` está prohibido `docker_compose_v2_pull`, y `docker_compose_v2` solo se admite con `pull: never`.

- [ ] **Step 1: Escribir el selftest (prueba en rojo)**

En `ansible/local/scripts/tags-contract.py`, antes de `def main() -> int:` agregar:
```python
def selftest() -> int:
    """Casos sinteticos: (tareas, errores esperados)."""
    casos = [
        ([{"name": "pull en start", "community.docker.docker_compose_v2_pull": {"project_src": "/x"}, "tags": ["start"]}], 1),
        ([{"name": "up sin pull never", "community.docker.docker_compose_v2": {"project_src": "/x"}, "tags": ["start"]}], 1),
        ([{"name": "up con pull missing", "community.docker.docker_compose_v2": {"project_src": "/x", "pull": "missing"}, "tags": ["start"]}], 1),
        ([{"name": "up con pull never", "community.docker.docker_compose_v2": {"project_src": "/x", "pull": "never"}, "tags": ["start"]}], 0),
        ([{"name": "pull en install", "community.docker.docker_compose_v2_pull": {"project_src": "/x"}, "tags": ["install"]}], 0),
    ]
    for tareas, esperados in casos:
        errores: list[str] = []
        walk(tareas, Path("selftest.yml"), errores)
        if len(errores) != esperados:
            print(f"tags-contract --selftest: FALLA en '{tareas[0]['name']}': {errores}", file=sys.stderr)
            return 1
    print(f"tags-contract --selftest: ok ({len(casos)} casos)")
    return 0
```
y al inicio de `main()`:
```python
    if "--selftest" in sys.argv[1:]:
        return selftest()
```

- [ ] **Step 2: Correrlo y ver que falla**

Run: `nix-shell --run 'python3 local/scripts/tags-contract.py --selftest'`
Expected: `FALLA en 'pull en start': []` (exit 1).

- [ ] **Step 3: Implementar las reglas**

En `DOWNLOAD_MODULES` agregar `"docker_compose_v2_pull",` (en orden alfabético, después de `"dnf",`).

En `walk`, justo después de
```python
        mod = module_of(task)
        if "start" in tags and mod in DOWNLOAD_MODULES:
            errors.append(f"{path}: el tag 'start' usa modulo de descarga '{mod}': {name}")
```
agregar:
```python
        if "start" in tags and mod == "docker_compose_v2":
            args = next(v for k, v in task.items() if k.split(".")[-1] == "docker_compose_v2")
            if not isinstance(args, dict) or args.get("pull") != "never":
                errors.append(f"{path}: el tag 'start' usa docker_compose_v2 sin 'pull: never': {name}")
```

En `ansible/Makefile`, el target `tags-contract` queda:
```make
tags-contract:
	@"$(PY)" "$(LOCAL)/scripts/tags-contract.py" --selftest
	@"$(PY)" "$(LOCAL)/scripts/tags-contract.py"
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --list-tasks --tags start >/dev/null
	@echo "tags-contract: ok (--list-tasks --tags start compila)"
```

- [ ] **Step 4: Verificar**

Run: `nix-shell --run 'make tags-contract'`
Expected: `tags-contract --selftest: ok (5 casos)`, luego `tags-contract: ok (... archivos de tareas)` y la línea final.

- [ ] **Step 5: Commit**

```bash
git add local/scripts/tags-contract.py Makefile
git commit -m "feat(ansible): el contrato de tags prohíbe descargas de Compose en start" -m "docker_compose_v2_pull cuenta como descarga y docker_compose_v2 en start exige pull: never (E1-8). Selftest con casos sintéticos."
```

---

### Task 4: Arnés y `honeypot-check` (primero la prueba, en rojo)

**Files:**
- Create: `ansible/local/scripts/honeypot-conf-check.py`, `ansible/local/scripts/honeypot-check.sh`
- Modify: `ansible/local/docker-compose.yml`, `ansible/local/inventory.yml`, `ansible/local/scripts/wazuh-agent-fixture.sh`, `ansible/Makefile`

**Interfaces:**
- Consumes: `group_vars/all.yml` (Tarea 2).
- Produces:
  - `make honeypot-apply TAGS=…`, `make honeypot-rehearse` y `make honeypot-check`;
  - `HONEYPOT_CHECKS="1 3"` para un subconjunto (por defecto `1 2 4 5 6 7 8 9`; el 3 lo llama `honeypot-rehearse` tras `install,config`);
  - `honeypot-check.sh` lee `honeypot_docker_version`, `honeypot_containerd_version` y `honeypot_compose_version` de `roles/honeypot/defaults/main.yml` con el formato `nombre: "valor"` en la primera columna. La Tarea 5 debe respetar ese formato;
  - el mensaje del rol que busca el check 9 contiene la frase exacta `el egreso sigue abierto`;
  - centinelas en `/etc/soc-tesis/`: `honeypot-started` y `honeypot-images`.

- [ ] **Step 1: Volúmenes de Docker para `honeyserver` en `ansible/local/docker-compose.yml`**

El servicio `honeyserver` queda así (el merge de YAML reemplaza la lista `volumes` de `x-vm`, por eso se repiten las dos primeras):
```yaml
  honeyserver:
    <<: *vm
    container_name: soc-local-honeyserver
    hostname: honeyserver
    environment:
      # El 22 es el señuelo; la administración va por el 22222 (A6/E1-2).
      SSHD_PORT: "22222"
    # Docker dentro del contenedor (rol honeypot): /var/lib/docker y
    # /var/lib/containerd en volumenes, para no apilar overlayfs sobre el
    # overlay del contenedor (Docker 29 usa el snapshotter de containerd).
    volumes:
      - ./.keys:/keys:ro
      - /sys/fs/cgroup:/sys/fs/cgroup:rw
      - honeyserver-docker:/var/lib/docker
      - honeyserver-containerd:/var/lib/containerd
    networks:
      operate:
        ipv4_address: 10.50.10.10
      install:
        gw_priority: 10
```
y al final del archivo:
```yaml
volumes:
  honeyserver-docker:
    name: soc-local-honeyserver-docker
  honeyserver-containerd:
    name: soc-local-honeyserver-containerd
```
`make down` ya usa `down -v`, así que `make clean` también borra estos volúmenes.

- [ ] **Step 2: `honeypot_enabled: false` en el inventario local**

En `ansible/local/inventory.yml`, el host `honeyserver` queda:
```yaml
        honeyserver:
          ansible_host: 10.50.10.10
          ansible_port: 22222
          honeypot_enabled: false # make honeypot-rehearse lo activa con -e; preflight no instala Docker
          wazuh_secrets_dir: /tmp/soc-local-secrets # authd.pass del ensayo (fuera del repo)
```

- [ ] **Step 3: El fixture de Wazuh usa los mismos archivos que el rol**

En `ansible/local/scripts/wazuh-agent-fixture.sh`, reemplazar el bloque
```bash
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
```
por
```bash
  # Mismos archivos y contenido que el rol honeypot (wazuh.asc y wazuh.list): si
  # difirieran, apt veria dos Signed-By para el mismo repo y fallaria.
  docker exec "$ctr" sh -c '
    set -e
    curl -fsS -o /usr/share/keyrings/wazuh.asc https://packages.wazuh.com/key/GPG-KEY-WAZUH
    chmod 644 /usr/share/keyrings/wazuh.asc
    echo "deb [signed-by=/usr/share/keyrings/wazuh.asc] https://packages.wazuh.com/4.x/apt/ stable main" \
      >/etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
  '
```
También cambiar la línea 2 del comentario de cabecera por:
```bash
# El rol `honeypot` lo instala de verdad; este fixture solo existe para el check 9 de wazuh-check.
```

- [ ] **Step 4: Crear `ansible/local/scripts/honeypot-conf-check.py`**

```python
#!/usr/bin/env python3
"""Check 5 de honeypot-check: ossec.conf del agente (spec honeypot §4.4, D4).

Se ejecuta DENTRO del contenedor:
  docker exec -i soc-local-honeyserver python3 - /var/ossec/etc/ossec.conf < honeypot-conf-check.py
ossec.conf admite varios bloques <ossec_config>; se envuelven en una raiz.
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

RELAY = "10.50.30.10"
JSON_FILES = {
    "/srv/soc-tesis/cowrie/log/cowrie.json": "cowrie",
    "/srv/soc-tesis/dionaea/lib/dionaea.json": "dionaea",
    "/srv/soc-tesis/tanner/log/tanner_report.json": "tanner",
}
MAILONEY_FILTER = "^soc-tesis-mailoney$"


def text(el: ET.Element | None, tag: str) -> str:
    return ((el.findtext(tag) if el is not None else None) or "").strip()


def main() -> int:
    raw = open(sys.argv[1], encoding="utf-8").read()
    root = ET.fromstring("<root>" + raw + "</root>")
    errs: list[str] = []

    addrs = [(e.text or "").strip() for e in root.iter("address")]
    if addrs != [RELAY]:
        errs.append(f"<server><address> debe ser solo {RELAY}; hay {addrs}")

    qs = [(e.text or "").strip() for e in root.iter("queue_size")]
    eps = [(e.text or "").strip() for e in root.iter("events_per_second")]
    if qs != ["100000"] or eps != ["500"]:
        errs.append(f"client_buffer: queue_size={qs} events_per_second={eps} (se esperaba 100000 y 500)")

    files = {text(lf, "location"): lf for lf in root.iter("localfile")}
    for loc, hp in JSON_FILES.items():
        lf = files.get(loc)
        if lf is None:
            errs.append(f"falta el localfile {loc}")
            continue
        if text(lf, "log_format") != "json":
            errs.append(f"{loc}: log_format no es json")
        if text(lf, "only-future-events") != "no":
            errs.append(f"{loc}: only-future-events no es 'no'")
        labels = {lb.get("key"): (lb.text or "").strip() for lb in lf.findall("label")}
        if labels != {"@honeypot": hp}:
            errs.append(f"{loc}: etiquetas {labels}; se esperaba solo @honeypot={hp}")

    journald = [lf for lf in root.iter("localfile") if text(lf, "location") == "journald"]
    if len(journald) != 1:
        errs.append(f"se esperaba exactamente un localfile de journald; hay {len(journald)}")
    else:
        lf = journald[0]
        flt = lf.find("filter")
        if text(lf, "log_format") != "journald":
            errs.append("journald: log_format no es journald")
        if flt is None or flt.get("field") != "CONTAINER_NAME" or (flt.text or "").strip() != MAILONEY_FILTER:
            errs.append(f"journald: falta <filter field=\"CONTAINER_NAME\">{MAILONEY_FILTER}</filter>")
        if text(lf, "only-future-events") != "no":
            errs.append("journald: only-future-events no es 'no'")
        if lf.findall("label"):
            errs.append("journald: no debe llevar <label> (solo funciona con log_format json)")

    for e in errs:
        print(e)
    if not errs:
        print("relay, client_buffer, 3 localfile json con @honeypot y journald de Mailoney")
    return 1 if errs else 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 5: Crear `ansible/local/scripts/honeypot-check.sh`**

```bash
#!/usr/bin/env bash
# Verifica el rol honeypot en el ensayo local (spec 2026-11-04-honeypot-role-design.md §6).
# Requiere make honeypot-rehearse (y antes make wazuh-rehearse). Subconjunto: HONEYPOT_CHECKS="1 2".
# El check 3 (todo dormido tras install,config) no va en la lista por defecto: lo llama
# honeypot-rehearse justo despues de la 1a pasada.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ansible_dir="$(cd "$here/../.." && pwd)"
repo="$(cd "$ansible_dir/.." && pwd)"
defaults="$ansible_dir/roles/honeypot/defaults/main.yml"
shared="$ansible_dir/group_vars/all.yml"
secrets="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
ctr=soc-local-honeyserver
mgr=soc-local-wazuh
attacker=soc-local-logrelay
hp_ip=10.50.10.10
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }
hs() { docker exec "$ctr" "$@"; }
var_of() { sed -n "s/^$2:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" 2>/dev/null | head -n1; }
banner() { docker exec "$attacker" timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2; head -n1 <&3" 2>/dev/null | tr -d '\r' || true; }

docker_version="$(var_of "$defaults" honeypot_docker_version)"
containerd_version="$(var_of "$defaults" honeypot_containerd_version)"
compose_version="$(var_of "$defaults" honeypot_compose_version)"
agent_version="$(var_of "$shared" wazuh_expected_version)-1"
mapfile -t images < <(sed -n 's/^[A-Z_]*_IMAGE=//p' "$repo/.env.example")

# 1. Paquetes en la version fijada, retenidos, y sin recomendados.
c1() {
  local holds row pkg want have
  holds="$(hs apt-mark showhold 2>/dev/null || true)"
  for row in "docker-ce $docker_version" "docker-ce-cli $docker_version" "containerd.io $containerd_version" \
             "docker-compose-plugin $compose_version" "wazuh-agent $agent_version"; do
    read -r pkg want <<<"$row"
    have="$(hs dpkg-query -W -f '${Version}' "$pkg" 2>/dev/null || true)"
    if [ -n "$want" ] && [ "$have" = "$want" ]; then good "$pkg $want"; else bad "$pkg en '$have', se esperaba '$want'"; fi
    if grep -qxF "$pkg" <<<"$holds"; then good "$pkg retenido"; else bad "$pkg no esta retenido"; fi
  done
  for pkg in docker-buildx-plugin docker-ce-rootless-extras; do
    if hs dpkg -s "$pkg" >/dev/null 2>&1; then bad "$pkg instalado (debia quedar fuera)"; else good "$pkg ausente"; fi
  done
}

# 2. RepoDigests iguales a .env.example (requiere el daemon arriba: tras start).
c2() {
  local ref pinned have
  [ "${#images[@]}" -eq 7 ] || bad ".env.example tiene ${#images[@]} imagenes, se esperaban 7"
  for ref in "${images[@]}"; do
    pinned="$(sed -E 's#:[^/@]+@#@#' <<<"$ref")"
    have="$(hs docker image inspect --format '{{join .RepoDigests " "}}' "$pinned" 2>/dev/null || true)"
    if tr ' ' '\n' <<<"$have" | grep -qxF "$pinned"; then good "digest $pinned"; else bad "imagen $pinned ausente o con otro digest ('$have')"; fi
  done
}

# 3. E1-3: tras install,config nada del senuelo activo ni habilitado.
c3() {
  local u
  for u in docker.service docker.socket containerd.service wazuh-agent.service; do
    if hs systemctl is-active --quiet "$u"; then bad "$u activo con el egreso abierto"; else good "$u inactivo"; fi
    if hs systemctl is-enabled --quiet "$u" 2>/dev/null; then bad "$u habilitado con el egreso abierto"; else good "$u deshabilitado"; fi
  done
  if hs test -e /etc/soc-tesis/honeypot-started; then bad "honeypot-started existe antes de start"; else good "sin honeypot-started"; fi
  if hs test -s /etc/soc-tesis/honeypot-images; then good "centinela de imagenes escrito"; else bad "falta /etc/soc-tesis/honeypot-images"; fi
}

# 4. Tras start: 7 contenedores sanos; el 22 lo atiende Cowrie; sshd del host en el 22222.
c4() {
  local n s22 s22222 eff
  n="$(hs docker ps --filter 'name=^soc-tesis-' --filter health=healthy --format '{{.Names}}' 2>/dev/null | wc -l)"
  if [ "$n" -eq 7 ]; then good "7 contenedores healthy"; else bad "$n contenedores healthy, se esperaban 7"; fi
  s22="$(banner "$hp_ip" 22)"
  s22222="$(banner "$hp_ip" 22222)"
  if [ -n "$s22" ] && [ -n "$s22222" ] && [ "$s22" != "$s22222" ]; then
    good "el 22 lo atiende el senuelo ('$s22'), no el sshd del host ('$s22222')"
  else
    bad "banners del 22 ('$s22') y del 22222 ('$s22222'): el senuelo no atiende el 22"
  fi
  eff="$(hs /usr/sbin/sshd -T 2>/dev/null | grep '^port ' || true)"
  if [ "$eff" = "port 22222" ]; then good "sshd del host solo en 22222"; else bad "sshd -T: '$eff'"; fi
}

# 5. ossec.conf del agente (D4).
c5() {
  local out
  if out="$(docker exec -i "$ctr" python3 - /var/ossec/etc/ossec.conf <"$here/honeypot-conf-check.py" 2>&1)"; then
    good "ossec.conf: $out"
  else
    bad "ossec.conf no cumple D4"; printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

# 6. authd.pass.
c6() {
  local meta have want
  meta="$(hs stat -c '%a %U:%G' /var/ossec/etc/authd.pass 2>/dev/null || true)"
  if [ "$meta" = "640 root:wazuh" ]; then good "authd.pass 640 root:wazuh"; else bad "authd.pass con permisos '$meta'"; fi
  have="$(hs sha256sum /var/ossec/etc/authd.pass 2>/dev/null | cut -d' ' -f1 || true)"
  want="$(sha256sum "$secrets/authd.pass" 2>/dev/null | cut -d' ' -f1 || true)"
  if [ -n "$have" ] && [ "$have" = "$want" ]; then good "authd.pass coincide con el del controlador"; else bad "authd.pass distinto del del controlador"; fi
}

# 7. El agente del honeyserver aparece activo en el Manager (a traves del relay).
c7() {
  local _
  for _ in $(seq 1 12); do
    if docker exec "$mgr" /var/ossec/bin/agent_control -l 2>/dev/null | grep -Eq 'Name: honeyserver, IP: any, Active'; then
      good "agente honeyserver activo en el Manager"; return
    fi
    sleep 5
  done
  bad "el agente honeyserver no aparece activo en agent_control -l"
}

# 8. Cada honeypot escribe su evento y wazuh-logcollector lo lee (D4).
c8() {
  local t0 f _ ok state
  t0="$(hs date +%s)"
  sleep 1
  docker exec "$attacker" timeout 10 bash -c "exec 3<>/dev/tcp/$hp_ip/22; printf 'SSH-2.0-soc-probe\r\n' >&3; sleep 3" || true
  docker exec "$attacker" timeout 10 bash -c "exec 3<>/dev/tcp/$hp_ip/21; printf 'USER soc-probe\r\n' >&3; sleep 3" || true
  docker exec "$attacker" curl -s -m 10 -o /dev/null "http://$hp_ip/soc-probe" || true
  docker exec "$attacker" timeout 10 bash -c "exec 3<>/dev/tcp/$hp_ip/25; printf 'HELO soc-probe\r\nQUIT\r\n' >&3; sleep 3" || true

  for f in cowrie/log/cowrie.json dionaea/lib/dionaea.json tanner/log/tanner_report.json; do
    ok=0
    for _ in $(seq 1 18); do
      if [ "$(hs stat -c %Y "/srv/soc-tesis/$f" 2>/dev/null || echo 0)" -ge "$t0" ]; then ok=1; break; fi
      sleep 10
    done
    if [ "$ok" -eq 1 ]; then good "$f recibio el evento de prueba"; else bad "$f no cambio tras el evento de prueba"; fi
  done
  if [ "$(hs journalctl CONTAINER_NAME=soc-tesis-mailoney --since "@$t0" -o cat --no-pager 2>/dev/null | grep -c . || true)" -gt 0 ]; then
    good "Mailoney escribio en journald"
  else
    bad "Mailoney no escribio en journald tras el evento de prueba"
  fi

  ok=0
  for _ in $(seq 1 9); do
    state="$(hs cat /var/ossec/var/run/wazuh-logcollector.state 2>/dev/null || true)"
    if [ -n "$state" ] && python3 - "$state" <<'PY'
import json, sys
seen = {}
def walk(x):
    if isinstance(x, dict):
        if "location" in x and "events" in x:
            seen[x["location"]] = max(seen.get(x["location"], 0), int(x["events"]))
        for v in x.values():
            walk(v)
    elif isinstance(x, list):
        for v in x:
            walk(v)
walk(json.loads(sys.argv[1]))
want = ["/srv/soc-tesis/cowrie/log/cowrie.json", "/srv/soc-tesis/dionaea/lib/dionaea.json",
        "/srv/soc-tesis/tanner/log/tanner_report.json", "journald"]
sys.exit(0 if all(seen.get(w, 0) > 0 for w in want) else 1)
PY
    then ok=1; break; fi
    sleep 10
  done
  if [ "$ok" -eq 1 ]; then good "wazuh-logcollector leyo eventos de los 4 localfile"; else bad "wazuh-logcollector.state sin eventos en los 4 localfile ('${state:0:300}')"; fi
}

# 9. Prueba negativa: con el egreso abierto, start falla en la sonda.
c9() {
  local out
  if [ -z "${ANSIBLE_INVENTORY:-}" ]; then bad "ejecuta este check via make honeypot-check (faltan las variables ANSIBLE_*)"; return; fi
  bash "$here/net-toggle.sh" install >/dev/null
  out="$(cd "$ansible_dir" && ansible-playbook site.yml --limit honeyserver --tags start -e honeypot_enabled=true 2>&1 || true)"
  bash "$here/net-toggle.sh" operate >/dev/null
  if grep -q 'el egreso sigue abierto' <<<"$out"; then good "start se niega a arrancar con el egreso abierto"; else bad "start no fallo en la sonda de egreso con el egreso abierto"; fi
}

for n in ${HONEYPOT_CHECKS:-1 2 4 5 6 7 8 9}; do "c$n"; done

if [ "$fail" -ne 0 ]; then
  echo "honeypot-check: FALLA" >&2
  exit 1
fi
echo "honeypot-check: ok"
```
Hacerlo ejecutable: `chmod +x local/scripts/honeypot-check.sh local/scripts/honeypot-conf-check.py`.

- [ ] **Step 6: Targets en `ansible/Makefile`**

En la lista `.PHONY`, agregar `honeypot-apply honeypot-rehearse honeypot-check` antes de `clean`. En `help`, debajo de la línea de `wazuh-apply`:
```make
	@echo "  make honeypot-rehearse  Docker, 7 imagenes y agente reales en honeyserver (requiere wazuh-rehearse; fuera de preflight)"
	@echo "  make honeypot-check     verifica el rol honeypot (HONEYPOT_CHECKS=\"1 2\" para un subconjunto)"
	@echo "  make honeypot-apply TAGS=install   aplica el rol honeypot con esos tags (iteracion)"
```
Y debajo del target `wazuh-rehearse`:
```make
honeypot-check:
	@bash "$(LOCAL)/scripts/honeypot-check.sh"

# Iteracion: aplica el rol honeypot con los tags indicados (por defecto install,config).
honeypot-apply: wazuh-secrets known-hosts
	@bash "$(LOCAL)/scripts/net-toggle.sh" install
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver --tags "$(or $(TAGS),install,config)" -e honeypot_enabled=true

honeypot-rehearse: wazuh-secrets known-hosts
	@mkdir -p "$(LOGS)"
	@docker exec soc-local-wazuh systemctl is-active --quiet wazuh-manager \
	  || { echo "FALLA: el Manager de Wazuh no esta activo en el contenedor wazuh (corre make wazuh-rehearse antes)" >&2; exit 1; }
	@echo "== Honeypot: egreso abierto (Docker, imagenes y agente) =="
	@bash "$(LOCAL)/scripts/net-toggle.sh" install
	@echo "== Honeypot 1a pasada (install,config): debe aplicar cambios =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver --tags install,config -e honeypot_enabled=true 2>&1 | tee "$(LOGS)/honeypot-pass1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/honeypot-pass1.log" changed
	@echo "== E1-3: nada del senuelo activo ni habilitado con el egreso abierto =="
	@HONEYPOT_CHECKS=3 bash "$(LOCAL)/scripts/honeypot-check.sh"
	@echo "== Honeypot 2a pasada: idempotente =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver --tags install,config -e honeypot_enabled=true 2>&1 | tee "$(LOGS)/honeypot-pass2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/honeypot-pass2.log" nochange
	@echo "== Honeypot --check --diff tras converger =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver --tags install,config -e honeypot_enabled=true --check --diff 2>&1 | tee "$(LOGS)/honeypot-check.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/honeypot-check.log" nochange
	@echo "== Honeypot: egreso cerrado y arranque en dos pasadas =="
	@bash "$(LOCAL)/scripts/net-toggle.sh" operate
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver --tags start -e honeypot_enabled=true 2>&1 | tee "$(LOGS)/honeypot-start1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/honeypot-start1.log" ok
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver --tags start -e honeypot_enabled=true 2>&1 | tee "$(LOGS)/honeypot-start2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/honeypot-start2.log" nochange
	@echo "== Honeypot: pasada completa sin tags con el egreso cerrado (Etapa 9) =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --limit honeyserver -e honeypot_enabled=true 2>&1 | tee "$(LOGS)/honeypot-full.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/honeypot-full.log" nochange
	@$(MAKE) --no-print-directory honeypot-check
	@echo "honeypot-rehearse: ok"
```

- [ ] **Step 7: Verificar que el arnés compila y que el check está en rojo**

Los cambios de `docker-compose.yml` y del fixture exigen recrear el entorno. Correr en segundo plano y esperar:
```bash
nix-shell --run 'make clean preflight' > /tmp/soc-preflight.log 2>&1; echo "exit=$?" >> /tmp/soc-preflight.log
```
Expected: `preflight: Etapa 0 OK` y `exit=0` (el rol `honeypot` sigue siendo el marcador, y con `honeypot_enabled` sin usar todavía no cambia nada).

Luego, también en segundo plano:
```bash
nix-shell --run 'make wazuh-rehearse' > /tmp/soc-wazuh.log 2>&1; echo "exit=$?" >> /tmp/soc-wazuh.log
```
Expected: `wazuh-rehearse: ok` (el check 9 sigue en verde con el fixture nuevo).

Y finalmente:
```bash
nix-shell --run 'bash -n local/scripts/honeypot-check.sh && shellcheck local/scripts/honeypot-check.sh && HONEYPOT_CHECKS="1 5" make honeypot-check'
```
Expected: `shellcheck` sin hallazgos; `honeypot-check: FALLA` con `docker-ce en ''…` y `ossec.conf no cumple D4` (el rol todavía no instala nada).

- [ ] **Step 8: Commit**

```bash
git add local/docker-compose.yml local/inventory.yml local/scripts/wazuh-agent-fixture.sh local/scripts/honeypot-conf-check.py local/scripts/honeypot-check.sh Makefile
git commit -m "test(ansible): arnés y honeypot-check del Honey-Server (en rojo)" -m "Volúmenes de Docker para honeyserver, honeypot_enabled en el inventario local, fixture de Wazuh con los mismos archivos que el rol y los 9 checks de la spec honeypot §6."
```

---

### Task 5: Rol `honeypot`, parte 1: instalación, imágenes y E1-3

**Files:**
- Create: `ansible/roles/honeypot/defaults/main.yml`
- Replace: `ansible/roles/honeypot/tasks/main.yml`
- Modify: `ansible/requirements.yml`

**Interfaces:**
- Consumes: `wazuh_expected_version` y `wazuh_secrets_dir` (Tarea 2); `.env.example`, `docker-compose.yml` y `config/` (Tarea 1).
- Produces:
  - `honeypot_started` (resultado de `stat` de `/etc/soc-tesis/honeypot-started`), que usan las Tareas 6 y 7 y el handler;
  - `/etc/soc-tesis/honeypot-uids.json` (`{"cowrie/log": ["UID", "GID"], ...}`), que lee la Tarea 6;
  - `/etc/soc-tesis/honeypot-images` (las 7 referencias separadas por espacios);
  - `honeypot_dir` con `docker-compose.yml`, `.env` y `config/`;
  - las variables `honeypot_image_env`, `honeypot_image_refs`, `honeypot_bind_dirs`, `honeypot_data_root`, `honeypot_relay_ip`, `honeypot_secrets_dir_real` y `honeypot_repo_root`.

- [ ] **Step 1: Confirmar la prueba en rojo**

Run: `nix-shell --run 'make honeypot-apply TAGS=install && HONEYPOT_CHECKS="1 3" make honeypot-check'`
Expected: `honeypot-check: FALLA` en los paquetes y en `falta /etc/soc-tesis/honeypot-images`.

- [ ] **Step 2: Crear `ansible/roles/honeypot/defaults/main.yml`**

```yaml
---
# Rol honeypot. Diseño: docs/superpowers/specs/2026-11-04-honeypot-role-design.md
honeypot_enabled: true

# Baseline D1 (17_SOFTWARE_BASELINE.md). Formato "nombre: valor" en la primera columna:
# lo leen pin-check.sh y honeypot-check.sh con sed.
honeypot_docker_version: "5:29.8.2-1~ubuntu.22.04~jammy"
honeypot_containerd_version: "2.3.6-1~ubuntu.22.04~jammy"
honeypot_compose_version: "5.6.0-1~ubuntu.22.04~jammy"
honeypot_docker_key_fingerprint: "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
honeypot_wazuh_key_fingerprint: "0DCFCA5547B19D2A6099506096B3EE5F29111145"
# ponytail: fecha copiada de la clave (gpg --show-keys, 2026-11-04); si Wazuh la re-firma
# con la misma huella, pin-check avisara de mas hasta actualizar este valor.
honeypot_wazuh_key_expires: "2027-05-15"

honeypot_package_specs:
  - "docker-ce={{ honeypot_docker_version }}"
  - "docker-ce-cli={{ honeypot_docker_version }}"
  - "containerd.io={{ honeypot_containerd_version }}"
  - "docker-compose-plugin={{ honeypot_compose_version }}"
  - "wazuh-agent={{ wazuh_expected_version }}-1"

honeypot_apt_sources:
  - name: docker
    key_url: https://download.docker.com/linux/ubuntu/gpg
    fingerprint: "{{ honeypot_docker_key_fingerprint }}"
    repo: "deb [arch=amd64 signed-by=/usr/share/keyrings/docker.asc] https://download.docker.com/linux/ubuntu jammy stable"
  - name: wazuh
    key_url: https://packages.wazuh.com/key/GPG-KEY-WAZUH
    fingerprint: "{{ honeypot_wazuh_key_fingerprint }}"
    repo: "deb [signed-by=/usr/share/keyrings/wazuh.asc] https://packages.wazuh.com/4.x/apt/ stable main"

honeypot_dir: /opt/soc-tesis
honeypot_data_root: /srv/soc-tesis
honeypot_relay_ip: "10.50.30.10"
honeypot_wait_timeout: 300
# Destinos fuera de Azure (E1-6): Allow-Out-AzureCloud-443 no los cubre.
honeypot_egress_probe_urls:
  - http://1.1.1.1
  - https://example.com

honeypot_repo_root: "{{ (playbook_dir ~ '/..') | realpath }}"
honeypot_secrets_dir_real: "{{ wazuh_secrets_dir | expanduser | realpath }}"
# Lineas *_IMAGE= de .env.example (D2): fuente unica de los 7 digests.
honeypot_image_env: >-
  {{ dict(lookup('ansible.builtin.file', honeypot_repo_root ~ '/.env.example').splitlines()
     | select('match', '^[A-Z_]+_IMAGE=') | map('split', '=')) }}
honeypot_image_refs: "{{ honeypot_image_env.values() | list }}"
# Directorios del bind (D4) y la imagen que escribe en cada uno.
honeypot_bind_dirs:
  - { dir: cowrie/log, image_var: COWRIE_IMAGE }
  - { dir: dionaea/lib, image_var: DIONAEA_IMAGE }
  - { dir: tanner/log, image_var: TANNER_IMAGE }
```

- [ ] **Step 3: Agregar `community.docker` a `ansible/requirements.yml`**

```yaml
# El controlador real (192.168.1.73) necesita estas colecciones: community.general para
# community.general.ufw y community.docker para el rol honeypot.
# En el nix-shell local ya vienen con el paquete `ansible`.
collections:
  - name: community.general
    version: "12.6.1"
  - name: community.docker
    version: "5.2.0"
```

- [ ] **Step 4: Reemplazar `ansible/roles/honeypot/tasks/main.yml`**

```yaml
---
# Rol honeypot: Docker + 7 imagenes fijadas (D2) + Wazuh Agent por el relay (D4).
# Diseño: docs/superpowers/specs/2026-11-04-honeypot-role-design.md
# E1-3: mientras el egreso este abierto, nada del señuelo queda activo ni
# habilitado. El daemon de Docker solo corre durante el pull de `install` y
# desde `start` en adelante. Señuelo en el 22, administración en el 22222 (A6/E1-2).
- name: Omitir el rol si está deshabilitado (el preflight local no instala Docker)
  ansible.builtin.meta: end_role
  when: not (honeypot_enabled | bool)
  tags: [install, config, start]

- name: Comprobar que la administración usa el puerto 22222
  ansible.builtin.assert:
    that:
      - ansible_port | default(22) | int == 22222
    fail_msg: "honeyserver debe administrarse por 22222; el 22 es el señuelo"
    quiet: true
  tags: [install, config, start]

- name: Asegurar el directorio de centinelas
  ansible.builtin.file:
    path: /etc/soc-tesis
    state: directory
    mode: "0755"
  tags: [install, config, start]

- name: Escribir el marcador del rol honeypot
  ansible.builtin.copy:
    dest: /etc/soc-tesis/honeypot
    content: "role=honeypot\n"
    mode: "0644"
  tags: [config]

- name: Leer si el señuelo ya arrancó alguna vez
  ansible.builtin.stat:
    path: /etc/soc-tesis/honeypot-started
  register: honeypot_started
  tags: [install, config, start]

# --- install: claves, repos y paquetes (único tag que descarga) -------------------------
- name: Instalar gnupg (verificación de las huellas)
  ansible.builtin.apt:
    name: gnupg
    state: present
    lock_timeout: 120
  tags: [install]

- name: Asegurar el directorio de claves descargadas (todavía sin confianza)
  ansible.builtin.file:
    path: /etc/soc-tesis/keys
    state: directory
    mode: "0755"
  tags: [install]

- name: Descargar las claves apt de Docker y Wazuh
  ansible.builtin.get_url:
    url: "{{ item.key_url }}"
    dest: "/etc/soc-tesis/keys/{{ item.name }}.asc"
    mode: "0644"
  loop: "{{ honeypot_apt_sources }}"
  loop_control:
    label: "{{ item.name }}"
  tags: [install]

- name: Leer la huella de cada clave descargada
  ansible.builtin.command: gpg --show-keys --with-colons /etc/soc-tesis/keys/{{ item.name }}.asc
  loop: "{{ honeypot_apt_sources }}"
  loop_control:
    label: "{{ item.name }}"
  register: honeypot_key_info
  changed_when: false
  check_mode: false
  tags: [install]

- name: Exigir la huella fijada en cada clave (clave primaria, 40 hex)
  ansible.builtin.assert:
    that:
      - (item.stdout_lines | select('match', '^fpr:') | first) == ('fpr:::::::::' ~ item.item.fingerprint ~ ':')
    fail_msg: >-
      La clave apt de {{ item.item.name }} ({{ item.item.key_url }}) no tiene la huella fijada
      {{ item.item.fingerprint }}: no se instala nada desde ese repo.
    quiet: true
  loop: "{{ honeypot_key_info.results }}"
  loop_control:
    label: "{{ item.item.name }}"
  tags: [install]

- name: Instalar las claves ya verificadas
  ansible.builtin.copy:
    src: "/etc/soc-tesis/keys/{{ item.name }}.asc"
    dest: "/usr/share/keyrings/{{ item.name }}.asc"
    remote_src: true
    owner: root
    group: root
    mode: "0644"
  loop: "{{ honeypot_apt_sources }}"
  loop_control:
    label: "{{ item.name }}"
  tags: [install]

- name: Agregar los repos de Docker y de Wazuh
  ansible.builtin.apt_repository:
    repo: "{{ item.repo }}"
    filename: "{{ item.name }}"
    update_cache: false
    state: present
  loop: "{{ honeypot_apt_sources }}"
  loop_control:
    label: "{{ item.name }}"
  register: honeypot_repos
  tags: [install]

- name: Leer las versiones instaladas de los paquetes fijados
  ansible.builtin.command: >-
    dpkg-query -W -f '${Package}=${Version}\n'
    {{ honeypot_package_specs | map('regex_replace', '=.*$', '') | join(' ') }}
  register: honeypot_dpkg
  changed_when: false
  failed_when: false
  check_mode: false
  tags: [install]

# apt solo refresca la caché si cambió un repo o falta un paquete en su versión:
# así la pasada completa con el egreso cerrado (Etapa 9) no sale a Internet.
- name: Instalar Docker, Compose y el Wazuh Agent en las versiones fijadas (D1)
  ansible.builtin.apt:
    name: "{{ honeypot_package_specs }}"
    install_recommends: false
    update_cache: true
    lock_timeout: 120
  when: honeypot_repos is changed or (honeypot_package_specs | difference(honeypot_dpkg.stdout_lines) | length > 0)
  tags: [install]

- name: Retener los paquetes fijados (hold)
  ansible.builtin.dpkg_selections:
    name: "{{ item | regex_replace('=.*$', '') }}"
    selection: hold
  loop: "{{ honeypot_package_specs }}"
  tags: [install]

# El policy-rc.d de common impide que el postinst arranque servicios, pero no que los
# habilite. Solo antes del primer start: después, install no toca servicios.
- name: Dejar Docker y el agente detenidos y deshabilitados (E1-3)
  ansible.builtin.systemd_service:
    name: "{{ item }}"
    state: stopped
    enabled: false
  loop:
    - docker.socket
    - docker.service
    - containerd.service
    - wazuh-agent.service
  when: not honeypot_started.stat.exists
  tags: [install]

# --- Proyecto compose (lo necesita el pull de install) ------------------------------------
- name: Crear el directorio del proyecto compose
  ansible.builtin.file:
    path: "{{ honeypot_dir }}"
    state: directory
    mode: "0755"
  tags: [install, config]

- name: Copiar docker-compose.yml y .env (sin secretos, D2)
  ansible.builtin.copy:
    src: "{{ honeypot_repo_root }}/{{ item.src }}"
    dest: "{{ honeypot_dir }}/{{ item.dest }}"
    owner: root
    group: root
    mode: "0644"
  loop:
    - { src: docker-compose.yml, dest: docker-compose.yml }
    - { src: .env.example, dest: .env }
  tags: [install, config]

- name: Copiar config/ de Dionaea y Tanner
  ansible.builtin.copy:
    src: "{{ honeypot_repo_root }}/config/"
    dest: "{{ honeypot_dir }}/config/"
    owner: root
    group: root
    mode: "0644"
    directory_mode: "0755"
  tags: [install, config]

# --- Imágenes por digest (solo si cambiaron) -------------------------------------------
- name: Leer el centinela de imágenes
  ansible.builtin.slurp:
    src: /etc/soc-tesis/honeypot-images
  register: honeypot_images_sentinel
  failed_when: false
  check_mode: false
  tags: [install]

- name: Descargar y verificar las imágenes (solo si cambiaron los digests)
  when: (honeypot_images_sentinel.content | default('') | b64decode) != (honeypot_image_refs | join(' '))
  tags: [install]
  block:
    - name: Arrancar Docker solo para el pull (sin habilitarlo)
      ansible.builtin.systemd_service:
        name: docker.service
        state: started
      tags: [install]

    - name: Descargar las 7 imágenes por digest (D2)
      community.docker.docker_compose_v2_pull:
        project_src: "{{ honeypot_dir }}"
        policy: missing
      tags: [install]

    - name: Leer los RepoDigests de cada imagen
      ansible.builtin.command: >-
        docker image inspect --format '{% raw %}{{join .RepoDigests " "}}{% endraw %}'
        {{ item | regex_replace(':[^/@]+@', '@') }}
      loop: "{{ honeypot_image_refs }}"
      register: honeypot_digests
      changed_when: false
      tags: [install]

    - name: Exigir el digest fijado en cada imagen (paso 5 del baseline)
      ansible.builtin.assert:
        that:
          - (item.item | regex_replace(':[^/@]+@', '@')) in item.stdout.split()
        fail_msg: "La imagen {{ item.item }} no tiene el digest de .env.example (RepoDigests: {{ item.stdout }})."
        quiet: true
      loop: "{{ honeypot_digests.results }}"
      loop_control:
        label: "{{ item.item }}"
      tags: [install]

    # Contenedor efímero y sin red: lee el usuario por defecto de la imagen.
    - name: Descubrir el UID:GID de las imágenes que escriben en el host (D4)
      ansible.builtin.command: >-
        docker run --rm --network none --entrypoint python3 {{ honeypot_image_env[item.image_var] }}
        -c 'import os; print(os.getuid(), os.getgid())'
      loop: "{{ honeypot_bind_dirs }}"
      loop_control:
        label: "{{ item.dir }}"
      register: honeypot_uid_probe
      changed_when: false
      tags: [install]

    - name: Guardar los UID:GID descubiertos (config los lee con el daemon apagado)
      ansible.builtin.copy:
        dest: /etc/soc-tesis/honeypot-uids.json
        content: >-
          {{ dict(honeypot_uid_probe.results | map(attribute='item.dir')
             | zip(honeypot_uid_probe.results | map(attribute='stdout') | map('split'))) | to_nice_json }}
        mode: "0644"
      tags: [install]

    - name: Escribir el centinela de imágenes
      ansible.builtin.copy:
        dest: /etc/soc-tesis/honeypot-images
        content: "{{ honeypot_image_refs | join(' ') }}"
        mode: "0644"
      tags: [install]

  always:
    - name: Volver a dormir Docker tras el pull, aunque haya fallado (E1-3)
      ansible.builtin.systemd_service:
        name: "{{ item }}"
        state: stopped
        enabled: false
      loop:
        - docker.socket
        - docker.service
        - containerd.service
      when: not honeypot_started.stat.exists
      tags: [install]
```

- [ ] **Step 5: Lint y contrato**

Run: `nix-shell --run 'make lint tags-contract'`
Expected: en verde. Si `ansible-lint` marca algo, corregir la tarea sin desactivar la regla.

- [ ] **Step 6: Primera pasada `install` y checks 1 y 3**

Run (en segundo plano; descarga ~2 GB):
```bash
nix-shell --run 'make honeypot-apply TAGS=install 2>&1 | tee local/.artifacts/hp-install1.log; bash local/scripts/recap-check.sh local/.artifacts/hp-install1.log changed && HONEYPOT_CHECKS="1 3" make honeypot-check' > /tmp/soc-hp5.log 2>&1; echo "exit=$?" >> /tmp/soc-hp5.log
```
Expected: `honeypot-check: ok` y `exit=0`. `cat` de `/etc/soc-tesis/honeypot-uids.json` en el contenedor muestra 3 entradas numéricas.

Si Docker no arranca dentro del contenedor (overlayfs, cgroups) o alguna imagen no trae `python3`, **detenerse y reportar** con `docker exec soc-local-honeyserver journalctl -u docker -n 50`.

- [ ] **Step 7: Segunda pasada sin cambios**

Run:
```bash
nix-shell --run 'make honeypot-apply TAGS=install 2>&1 | tee local/.artifacts/hp-install2.log; bash local/scripts/recap-check.sh local/.artifacts/hp-install2.log nochange'
```
Expected: exit 0 (`changed=0`: el bloque de imágenes se salta por el centinela y `apt` no corre).

- [ ] **Step 8: Commit**

```bash
git add roles/honeypot/defaults/main.yml roles/honeypot/tasks/main.yml requirements.yml
git commit -m "feat(ansible): rol honeypot, instalación con claves verificadas e imágenes por digest" -m "Paquetes fijados y retenidos, Docker y el agente dormidos durante la ventana (E1-3), pull condicionado por centinela con verificación de RepoDigests y UID de las imágenes."
```

---

### Task 6: Rol `honeypot`, parte 2: configuración y secretos

**Files:**
- Modify: `ansible/roles/honeypot/tasks/main.yml` (se agrega al final)
- Create: `ansible/roles/honeypot/handlers/main.yml`

**Interfaces:**
- Consumes: `honeypot_started`, `/etc/soc-tesis/honeypot-uids.json`, `honeypot_bind_dirs`, `honeypot_data_root`, `honeypot_relay_ip`, `honeypot_secrets_dir_real` y `honeypot_repo_root` (Tarea 5).
- Produces: el handler `Reiniciar wazuh-agent`; `ossec.conf` del agente con D4; `/var/ossec/etc/authd.pass`; los directorios `{{ honeypot_data_root }}/{cowrie/log,dionaea/lib,tanner/log}`.

- [ ] **Step 1: Confirmar la prueba en rojo**

Run: `nix-shell --run 'HONEYPOT_CHECKS="5 6" make honeypot-check'`
Expected: `FALLA` en `ossec.conf` (address `MANAGER_IP` o la del fixture, sin `localfile` de D4) y en `authd.pass`.

- [ ] **Step 2: Crear `ansible/roles/honeypot/handlers/main.yml`**

```yaml
---
# E1-3: solo se reinicia si el señuelo ya arrancó alguna vez. Durante la ventana
# de egreso el agente sigue dormido y toma la configuración en `start`.
- name: Reiniciar wazuh-agent
  ansible.builtin.systemd_service:
    name: wazuh-agent
    state: restarted
  when: honeypot_started.stat.exists
```

- [ ] **Step 3: Agregar al final de `ansible/roles/honeypot/tasks/main.yml`**

```yaml
# --- config: no descarga ni arranca -----------------------------------------------------
- name: Leer los UID:GID descubiertos en install
  ansible.builtin.slurp:
    src: /etc/soc-tesis/honeypot-uids.json
  register: honeypot_uids_file
  failed_when: false
  check_mode: false
  tags: [config]

- name: Exigir los UID:GID descubiertos
  ansible.builtin.assert:
    that: honeypot_uids_file.content is defined
    fail_msg: "Falta /etc/soc-tesis/honeypot-uids.json: corre antes --tags install (los UID se leen con el daemon arriba)."
    quiet: true
  tags: [config]

- name: Crear los directorios del bind con el dueño de cada imagen (D4)
  ansible.builtin.file:
    path: "{{ honeypot_data_root }}/{{ item.dir }}"
    state: directory
    owner: "{{ (honeypot_uids_file.content | b64decode | from_json)[item.dir][0] }}"
    group: "{{ (honeypot_uids_file.content | b64decode | from_json)[item.dir][1] }}"
    mode: "0755"
  loop: "{{ honeypot_bind_dirs }}"
  loop_control:
    label: "{{ item.dir }}"
  tags: [config]

- name: Apuntar el agente al relay (D4)
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '(<server>\s*<address>)[^<]*(</address>)'
    replace: '\g<1>{{ honeypot_relay_ip }}\g<2>'
  notify: Reiniciar wazuh-agent
  tags: [config]

- name: Fijar el client_buffer de D4 (cola 100000, 500 EPS)
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '(?s)(<client_buffer>(?:(?!</client_buffer>).)*?<{{ item.tag }}>)\s*\d+\s*(</{{ item.tag }}>)'
    replace: '\g<1>{{ item.value }}\g<2>'
  loop:
    - { tag: queue_size, value: 100000 }
    - { tag: events_per_second, value: 500 }
  notify: Reiniciar wazuh-agent
  tags: [config]

# El agente 4.14.9 trae un localfile de journald SIN filtro (todo el journal del sistema
# iria al Manager: ruido y contra la minimizacion de datos, doc 19 §7). Se quita para que
# quede uno solo, el de Mailoney. La regex exige el orden y los hijos del bloque original
# (log_format, location, nada mas), asi que nunca coincide con el nuestro. Verificado
# contra el ossec.conf real: 1 coincidencia antes, 0 despues.
- name: Quitar el localfile de journald sin filtro que trae el paquete
  ansible.builtin.replace:
    path: /var/ossec/etc/ossec.conf
    regexp: '[ \t]*<localfile>\s*<log_format>journald</log_format>\s*<location>journald</location>\s*</localfile>[ \t]*\n?'
    replace: ''
  notify: Reiniciar wazuh-agent
  tags: [config]

- name: Declarar los localfile de los honeypots (D4)
  ansible.builtin.blockinfile:
    path: /var/ossec/etc/ossec.conf
    marker: "<!-- {mark} SOC-TESIS D4 localfile (rol honeypot) -->"
    insertafter: EOF
    block: |
      <ossec_config>
      {% for item in [('cowrie/log/cowrie.json', 'cowrie'), ('dionaea/lib/dionaea.json', 'dionaea'), ('tanner/log/tanner_report.json', 'tanner')] %}
        <localfile>
          <location>{{ honeypot_data_root }}/{{ item[0] }}</location>
          <log_format>json</log_format>
          <only-future-events>no</only-future-events>
          <label key="@honeypot">{{ item[1] }}</label>
        </localfile>
      {% endfor %}
        <!-- Mailoney por journald (decisión 2026-11-04): <label> solo aplica a json. -->
        <localfile>
          <location>journald</location>
          <log_format>journald</log_format>
          <only-future-events>no</only-future-events>
          <filter field="CONTAINER_NAME">^soc-tesis-mailoney$</filter>
        </localfile>
      </ossec_config>
  notify: Reiniciar wazuh-agent
  tags: [config]

- name: Leer ossec.conf para verificarlo
  ansible.builtin.slurp:
    src: /var/ossec/etc/ossec.conf
  register: honeypot_ossec
  check_mode: false
  tags: [config]

- name: Comprobar que ossec.conf quedó con los valores de D4
  ansible.builtin.assert:
    that:
      - (honeypot_ossec.content | b64decode) is search('<address>' ~ honeypot_relay_ip ~ '</address>')
      - (honeypot_ossec.content | b64decode) is search('<queue_size>100000</queue_size>')
      - (honeypot_ossec.content | b64decode) is search('<events_per_second>500</events_per_second>')
      - (honeypot_ossec.content | b64decode | regex_findall('<location>journald</location>') | length) == 1
    fail_msg: >-
      ossec.conf no tiene los valores de D4: o las sustituciones no coincidieron con el formato del
      archivo instalado, o el localfile de journald del paquete cambio de forma y la tarea que lo
      quita ya no lo reconoce (debe quedar uno solo, el de Mailoney). Revisa
      /var/ossec/etc/ossec.conf y reporta antes de cambiar el rol.
  tags: [config]

- name: Validar la configuración del agente
  ansible.builtin.command: /var/ossec/bin/wazuh-logcollector -t
  changed_when: false
  check_mode: false
  tags: [config]

- name: Comprobar que el directorio de secretos está fuera del repositorio
  ansible.builtin.assert:
    that:
      - not ((honeypot_secrets_dir_real ~ '/').startswith(honeypot_repo_root ~ '/'))
    fail_msg: >-
      wazuh_secrets_dir ({{ honeypot_secrets_dir_real }}) está dentro del repositorio ({{ honeypot_repo_root }}):
      los secretos nunca pueden vivir en el repo.
  delegate_to: localhost
  become: false
  run_once: true
  tags: [config]

- name: Leer authd.pass en el controlador
  ansible.builtin.stat:
    path: "{{ honeypot_secrets_dir_real }}/authd.pass"
  register: honeypot_authd_local
  delegate_to: localhost
  become: false
  tags: [config]

- name: Exigir que authd.pass exista en el controlador
  ansible.builtin.assert:
    that: honeypot_authd_local.stat.exists
    fail_msg: "Falta {{ honeypot_secrets_dir_real }}/authd.pass (D8: el mismo que entrega el rol wazuh)."
  tags: [config]

- name: Entregar authd.pass (contraseña de enrolamiento)
  ansible.builtin.copy:
    src: "{{ honeypot_secrets_dir_real }}/authd.pass"
    dest: /var/ossec/etc/authd.pass
    owner: root
    group: wazuh
    mode: "0640"
  no_log: true
  notify: Reiniciar wazuh-agent
  tags: [config]
```

- [ ] **Step 4: Lint, contrato y aplicación**

Run:
```bash
nix-shell --run 'make lint tags-contract && make honeypot-apply TAGS=install,config 2>&1 | tee local/.artifacts/hp-config1.log; bash local/scripts/recap-check.sh local/.artifacts/hp-config1.log changed && HONEYPOT_CHECKS="3 5 6" make honeypot-check'
```
Expected: lint en verde; `honeypot-check: ok` (el 3 sigue en verde: config no arrancó nada, y el handler se saltó porque no existe `honeypot-started`).

Si el assert de `journald` falla porque el paquete trae su propio `localfile` de `journald`, **detenerse y reportar** con `docker exec soc-local-honeyserver grep -n -B2 -A6 '<location>journald' /var/ossec/etc/ossec.conf`.

- [ ] **Step 5: Segunda pasada sin cambios**

Run:
```bash
nix-shell --run 'make honeypot-apply TAGS=install,config 2>&1 | tee local/.artifacts/hp-config2.log; bash local/scripts/recap-check.sh local/.artifacts/hp-config2.log nochange'
```
Expected: exit 0.

- [ ] **Step 6: Commit**

```bash
git add roles/honeypot/tasks/main.yml roles/honeypot/handlers/main.yml
git commit -m "feat(ansible): rol honeypot, configuración del agente y entrega de authd.pass" -m "Directorios del bind con el UID de cada imagen, ossec.conf con el relay, client_buffer y localfile de D4 (Mailoney por journald), y authd.pass desde el controlador con no_log. Sin arranques durante la ventana (E1-3)."
```

---

### Task 7: Rol `honeypot`, parte 3: arranque y ensayo completo

**Files:**
- Modify: `ansible/roles/honeypot/tasks/main.yml` (se agrega al final)

**Interfaces:**
- Consumes: todo lo anterior; `honeypot_egress_probe_urls`, `honeypot_wait_timeout` y `honeypot_dir`.
- Produces: el centinela `/etc/soc-tesis/honeypot-started`, y el mensaje con `el egreso sigue abierto` (lo busca el check 9).

- [ ] **Step 1: Confirmar la prueba en rojo**

Run: `nix-shell --run 'bash local/scripts/net-toggle.sh operate && HONEYPOT_CHECKS="4 7" make honeypot-check'`
Expected: `FALLA`: 0 contenedores sanos; el agente no aparece activo (el rol lo dejó dormido).

- [ ] **Step 2: Agregar al final de `ansible/roles/honeypot/tasks/main.yml`**

```yaml
# --- start: nunca descarga ----------------------------------------------------------------
- name: Sondear el egreso a Internet (debe estar cerrado, E1-3/E1-6)
  ansible.builtin.uri:
    url: "{{ item }}"
    method: HEAD
    timeout: 5
    status_code: [-1]
  loop: "{{ honeypot_egress_probe_urls }}"
  register: honeypot_egress
  failed_when: false
  check_mode: false
  tags: [start]

- name: Exigir el egreso cerrado antes de arrancar el señuelo
  ansible.builtin.assert:
    that:
      - honeypot_egress.results | rejectattr('status', 'equalto', -1) | list | length == 0
    fail_msg: >-
      E1-3: el egreso sigue abierto (responden
      {{ honeypot_egress.results | rejectattr('status', 'equalto', -1) | map(attribute='item') | join(', ') }}).
      Cierra la ventana (terraform apply -var maintenance_egress=false) antes de arrancar el señuelo.
  tags: [start]

- name: Habilitar y arrancar Docker
  ansible.builtin.systemd_service:
    name: "{{ item }}"
    enabled: true
    state: started
  loop:
    - containerd.service
    - docker.socket
    - docker.service
  tags: [start]

- name: Levantar el señuelo sin descargar nada (espera a los healthchecks)
  community.docker.docker_compose_v2:
    project_src: "{{ honeypot_dir }}"
    state: present
    pull: never
    build: never
    wait: true
    wait_timeout: "{{ honeypot_wait_timeout }}"
  tags: [start]

- name: Habilitar y arrancar el Wazuh Agent
  ansible.builtin.systemd_service:
    name: wazuh-agent
    enabled: true
    state: started
  tags: [start]

- name: Esperar a que el agente quede conectado por el relay (D4)
  ansible.builtin.command: grep -qx "status='connected'" /var/ossec/var/run/wazuh-agentd.state
  register: honeypot_agent_state
  until: honeypot_agent_state.rc == 0
  retries: 30
  delay: 10
  changed_when: false
  check_mode: false
  tags: [start]

- name: Marcar que el señuelo arrancó (desde ahora install no toca servicios)
  ansible.builtin.copy:
    dest: /etc/soc-tesis/honeypot-started
    content: "started\n"
    mode: "0644"
  tags: [start]
```

**Nota sobre la sonda:** `uri` devuelve `status: -1` cuando no hay conexión. Con `status_code: [-1]` y `failed_when: false`, cualquier respuesta HTTP real (200, 301, 403…) cuenta como egreso abierto.

- [ ] **Step 3: Lint y contrato**

Run: `nix-shell --run 'make lint tags-contract'`
Expected: en verde (el contrato acepta `docker_compose_v2` con `pull: never` en `start`).

- [ ] **Step 4: Ensayo completo desde cero**

El ensayo exige un `honeyserver` limpio. Correr en segundo plano, uno tras otro, y esperar a cada uno:
```bash
nix-shell --run 'make clean preflight' > /tmp/soc-preflight.log 2>&1; echo "exit=$?" >> /tmp/soc-preflight.log
nix-shell --run 'make wazuh-rehearse' > /tmp/soc-wazuh.log 2>&1; echo "exit=$?" >> /tmp/soc-wazuh.log
nix-shell --run 'make honeypot-rehearse' > /tmp/soc-honeypot.log 2>&1; echo "exit=$?" >> /tmp/soc-honeypot.log
```
Expected: los tres con `exit=0`. El último termina con `honeypot-check: ok` (checks 1, 2, 4, 5, 6, 7, 8 y 9) y `honeypot-rehearse: ok`. La pasada completa sin tags da `changed=0`.

Si falla un check, leer el `FALLA:` en `/tmp/soc-honeypot.log`. Si la causa es un supuesto del plan (formato de `wazuh-logcollector.state`, un healthcheck sin `python3`, `tanner_report.json` que no se escribe en 3 minutos), **detenerse y reportar con evidencia**; no ajustar el check.

- [ ] **Step 5: Commit**

```bash
git add roles/honeypot/tasks/main.yml
git commit -m "feat(ansible): rol honeypot, arranque con sonda de egreso y compose sin descargas" -m "start exige el egreso cerrado (E1-3/E1-6), habilita Docker, levanta el compose con pull never y wait, y espera al agente conectado por el relay. make honeypot-rehearse en verde."
```

---

### Task 8: `pin-check` de Docker, documentación y refinamientos de la spec

**Files:**
- Modify: `ansible/local/scripts/pin-check.sh`, `ansible/PIPELINE.md`, `ansible/local/README.md`, `docs/superpowers/specs/2026-11-04-honeypot-role-design.md`

**Interfaces:**
- Consumes: `roles/honeypot/defaults/main.yml` (Tarea 5) y `group_vars/all.yml` (Tarea 2).
- Produces: `make pin-check` comprueba `docker-ce`, `docker-ce-cli`, `containerd.io`, `docker-compose-plugin` y `wazuh-agent`, y avisa de la caducidad de la clave de Wazuh. `PIN_CHECK_HONEYPOT_DEFAULTS` permite apuntar a otro archivo de defaults (para la prueba negativa).

- [ ] **Step 1: Prueba negativa (en rojo)**

```bash
sed 's/^honeypot_containerd_version: .*/honeypot_containerd_version: "0.0.0-1~ubuntu.22.04~jammy"/' roles/honeypot/defaults/main.yml > /tmp/hp-bad-defaults.yml
nix-shell --run 'PIN_CHECK_HONEYPOT_DEFAULTS=/tmp/hp-bad-defaults.yml make pin-check'; echo "exit=$?"
```
Expected: `pin-check: ok` y `exit=0`. Todavía no comprueba Docker; esa es la falla que hay que corregir.

- [ ] **Step 2: Agregar a `ansible/local/scripts/pin-check.sh`**

Antes de la línea `wazuh_defaults="${PIN_CHECK_WAZUH_DEFAULTS:-...}"`, agregar `indice=""` (lo reusa el bloque nuevo). Después del bloque de Wazuh y antes de `if [ "$fail" -ne 0 ]; then`, agregar:
```bash
# --- Rol honeypot: Docker (indice del repo de Docker) y wazuh-agent (indice de Wazuh) ---
hp_defaults="${PIN_CHECK_HONEYPOT_DEFAULTS:-$root/roles/honeypot/defaults/main.yml}"
docker_index="https://download.docker.com/linux/ubuntu/dists/jammy/stable/binary-amd64/Packages"
var_of() { sed -n "s/^$2:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" | head -n1; }
en_indice() { awk -v p="$1" -v v="$2" '/^Package: /{pkg=$2} /^Version: /{if (pkg == p && $2 == v) f=1} END{exit !f}'; }

if [ ! -f "$hp_defaults" ]; then
  echo "aviso: $hp_defaults no existe todavia; se omite la comprobacion de Docker"
else
  dindice="$(curl -fsSL --max-time 60 "$docker_index" 2>/dev/null || true)"
  if [ -z "$dindice" ]; then
    echo "FALLA: no se pudo leer el indice de Docker ($docker_index); pin-check necesita Internet" >&2
    fail=1
  else
    for fila in "docker-ce honeypot_docker_version" "docker-ce-cli honeypot_docker_version" \
                "containerd.io honeypot_containerd_version" "docker-compose-plugin honeypot_compose_version"; do
      read -r pkg variable <<<"$fila"
      want="$(var_of "$hp_defaults" "$variable")"
      if [ -z "$want" ]; then
        echo "FALLA: '$variable' no esta definida en $hp_defaults" >&2; fail=1; continue
      fi
      if en_indice "$pkg" "$want" <<<"$dindice"; then
        echo "ok: $pkg $want disponible (indice de Docker, $variable)"
      else
        echo "FALLA: $pkg no tiene la version fijada $want en el indice de Docker ($variable)" >&2; fail=1
      fi
    done
  fi

  if [ -n "$indice" ] && [ -n "${wazuh_want:-}" ]; then
    if en_indice wazuh-agent "${wazuh_want}-1" <<<"$indice"; then
      echo "ok: wazuh-agent ${wazuh_want}-1 disponible (indice de Wazuh)"
    else
      echo "FALLA: wazuh-agent ${wazuh_want}-1 no esta en el indice de Wazuh" >&2; fail=1
    fi
  fi

  expira="$(var_of "$hp_defaults" honeypot_wazuh_key_expires)"
  if [ -n "$expira" ]; then
    dias=$(( ( $(date -d "$expira" +%s) - $(date +%s) ) / 86400 ))
    if [ "$dias" -lt 60 ]; then
      echo "aviso: la clave apt de Wazuh caduca el $expira (en $dias dias): verifica la nueva y actualiza honeypot_wazuh_key_fingerprint y honeypot_wazuh_key_expires" >&2
    fi
  fi
fi
```

- [ ] **Step 3: Verificar las dos direcciones**

```bash
nix-shell --run 'PIN_CHECK_HONEYPOT_DEFAULTS=/tmp/hp-bad-defaults.yml make pin-check'; echo "exit=$?"
nix-shell --run 'make pin-check'; echo "exit=$?"
nix-shell --run 'shellcheck local/scripts/pin-check.sh'
rm -f /tmp/hp-bad-defaults.yml
```
Expected:
- 1ª corrida: `FALLA: containerd.io no tiene la version fijada 0.0.0-1~ubuntu.22.04~jammy…` y `exit=1`.
- 2ª corrida: 4 líneas `ok:` de Docker, `ok: wazuh-agent 4.14.9-1 disponible`, sin aviso de caducidad (faltan más de 60 días), `pin-check: ok` y `exit=0`.
- `shellcheck` sin hallazgos.

- [ ] **Step 4: `ansible/PIPELINE.md`**

En la Etapa 6, reemplazar la fila
```
| **Honeypot apagado** (E1-3): `systemctl is-active` y `docker ps` en honeyserver | ningún servicio del señuelo activo ni habilitado |
```
por
```
| **Honeypot apagado** (E1-3): `docker.service`, `docker.socket`, `containerd.service` y `wazuh-agent` en honeyserver | inactivos **y** deshabilitados; existe `/etc/soc-tesis/honeypot-images` (7 digests de `.env.example` verificados por `RepoDigests`) |
```
En la Etapa 8, reemplazar la fila
```
| Honeypot | el señuelo escucha en el 22 y la administración sigue en el 22222 |
```
por
```
| Honeypot | el rol se niega a arrancar si responde `http://1.1.1.1` o `https://example.com` (egreso abierto); `compose up` con `pull: never` deja los 7 contenedores `healthy`; el señuelo atiende el 22 y la administración sigue en el 22222; el agente queda `connected` por el relay |
```
En "Qué se replica en la rama", reemplazar
```
ni Docker-in-Docker del honeypot si se usan contenedores.
```
por
```
ni el pull real a través de `Allow-Out-Maintenance-Egress` (Docker dentro del contenedor `honeyserver` sí se ejercita con `make honeypot-rehearse`).
```

- [ ] **Step 5: `ansible/local/README.md`**

Agregar al final:
```markdown
## Rol honeypot: `make honeypot-rehearse` y `make honeypot-check`

Docker, las 7 imágenes de D2 y el Wazuh Agent reales corren dentro del contenedor `honeyserver`, con `/var/lib/docker` y `/var/lib/containerd` en volúmenes (sin overlayfs sobre overlayfs). **No** forma parte de `preflight`: el inventario local marca `honeypot_enabled: false`.

Flujo: `make clean preflight`, `make wazuh-rehearse` (el agente necesita el Manager) y luego `make honeypot-rehearse`:
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
4. 7 contenedores `healthy`, el 22 atendido por el señuelo y sshd solo en el 22222;
5. `ossec.conf` con el relay, `client_buffer` y los `localfile` de D4;
6. `authd.pass`;
7. el agente activo en el Manager;
8. un evento de prueba por honeypot escrito y leído por `wazuh-logcollector`;
9. que `start` se niegue a arrancar con el egreso abierto.

Qué NO valida: el NSG real de Azure, el pull a través de `Allow-Out-Maintenance-Egress`, el ciclo `deallocate`/`start` con `restart: unless-stopped`, el tráfico real de Internet, ni alertas en el Manager (no hay reglas por honeypot todavía).
```

- [ ] **Step 6: Registrar los refinamientos en la spec**

En `docs/superpowers/specs/2026-11-04-honeypot-role-design.md`, agregar al final:
```markdown
## 9. Refinamientos del plan de implementación (2026-11-04)

1. **`honeypot_enabled`** (por defecto `true`; `false` en el inventario local) para que `preflight` no instale Docker, igual que `wazuh_enabled`. `make honeypot-rehearse` lo activa con `-e`.
2. **Docker dentro del contenedor:** `/var/lib/docker` y `/var/lib/containerd` van en volúmenes, en lugar del driver `vfs` de §6. Así no se apila overlayfs y se prueba el mismo snapshotter que en Azure.
3. **UID de las imágenes:** se lee con `docker run --rm --network none --entrypoint python3 …`. Es un contenedor efímero y sin red, no un servicio del señuelo; E1-3 se mantiene.
4. **`apt` sin red en la Etapa 9:** solo refresca la caché si cambió un repo o falta un paquete en su versión exacta.
5. **Check 8:** sin reglas por honeypot (fuera de alcance, §8) no hay alerta en `alerts.json`. El check comprueba que cada honeypot escribe su evento y que `wazuh-logcollector` lo leyó. El transporte hasta el Manager lo prueba el check 7.
6. **Un solo `localfile` de `journald`:** el rol falla si `ossec.conf` trae otro además del de Mailoney.
7. **Fixture de `wazuh-rehearse`:** usa `wazuh.asc` y `wazuh.list`, iguales a los del rol, para que `apt` no vea dos `Signed-By`.
8. **`wazuh_expected_version` y `wazuh_secrets_dir`** viven en `ansible/group_vars/all.yml`.
```
Y cambiar la línea `**Estado:**` por:
```markdown
**Estado:** implementado en la rama `practica/ansible-local` (plan `docs/superpowers/plans/2026-11-04-honeypot-role.md`); refinamientos en §9.
```

- [ ] **Step 7: Verificación final**

Run: `nix-shell --run 'make lint tags-contract secret-scan'`
Expected: en verde.

- [ ] **Step 8: Commit**

```bash
git add local/scripts/pin-check.sh PIPELINE.md local/README.md ../docs/superpowers/specs/2026-11-04-honeypot-role-design.md
git commit -m "docs(ansible): pin-check de Docker, Etapas 6 y 8 y refinamientos de la spec del honeypot" -m "pin-check verifica docker-ce, docker-ce-cli, containerd.io, compose y wazuh-agent, y avisa de la caducidad de la clave de Wazuh. README del ensayo y spec §9."
```

---

## Self-Review

**Cobertura de la spec:**

| Sección | Tarea |
|---|---|
| §2 Enfoque 1 (daemon solo durante el pull y desde `start`) | Tarea 5 (bloque `block`/`always` y tarea de servicios dormidos) |
| §2 Versión del agente con `wazuh_expected_version` | Tareas 2 y 5 |
| §2 Mailoney por `journald` sin etiqueta | Tarea 6 (bloque `localfile`) |
| §2 `containerd.io` 2.3.6-1 | Tarea 5 (defaults) y Tarea 8 (`pin-check`) |
| §2 Prerrequisito: compose versionado | Tarea 1 |
| §3 Variables, `group_vars/all.yml` y centinelas | Tareas 2 y 5 |
| §4.1 Claves con huella, repos, `install_recommends: false`, `hold`, servicios dormidos | Tarea 5 |
| §4.2 Pull condicionado, `RepoDigests`, UID en `install`, `always` | Tarea 5 |
| §4.3 Directorios con UID, copia del proyecto, handlers solo si arrancó | Tareas 5 y 6 |
| §4.4 `ossec.conf` y `authd.pass` | Tarea 6 |
| §4.5 Sonda de egreso, Docker, `compose up` con `pull: never` y `wait`, agente conectado, `honeypot-started` | Tarea 7 |
| §5 Casos límite (pull fallido, 2ª pasada, imagen faltante, healthcheck, egreso abierto, UID ausente, relay caído) | Tareas 5, 6 y 7, y pasada completa en la Tarea 4 |
| §6 Ensayo y 9 checks | Tareas 4 y 7 (check 8 refinado, §9.5) |
| §7 Lint, contrato de tags (`docker_compose_v2_pull`), `PIPELINE.md`, comentario del rol, `community.docker`, `pin-check` | Tareas 3, 5 y 8 |

**Placeholders:** ninguno. Cada paso trae el código o el comando completo.

**Consistencia de nombres:**
- `honeypot_started`, `honeypot_image_env`, `honeypot_image_refs`, `honeypot_bind_dirs`, `honeypot_uids_file`, `honeypot_secrets_dir_real` y `honeypot_repo_root` se definen en la Tarea 5 y se usan igual en las 6 y 7.
- Los centinelas `honeypot-started`, `honeypot-images` y `honeypot-uids.json` se nombran igual en el rol y en `honeypot-check.sh`.
- La frase `el egreso sigue abierto` está en el `fail_msg` de la Tarea 7 y en el check 9.

**Hallazgo fuera de alcance (no se corrige aquí):** el rol `common` instala con `cache_valid_time: 3600`. En una pasada completa con el egreso cerrado y más de una hora después del último `apt-get update` (la Etapa 9 real), `common` intentará refrescar la caché y fallará. En el ensayo no se nota porque todo corre dentro de la misma hora. Hay que corregirlo en `common` con el mismo patrón de la Tarea 5.
