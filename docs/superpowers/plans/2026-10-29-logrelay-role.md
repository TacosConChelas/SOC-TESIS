# Rol `logrelay` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reemplazar el rol marcador `logrelay` por un NGINX `stream` L4 real (1514/1515 → Manager Wazuh), probado en los contenedores locales con `make relay-check`.

**Architecture:** Rol Ansible con plantilla Jinja del `nginx.conf` completo (solo `events` y `stream`), tags `install`/`config`/`start` según E1-8, y UFW solo en host real. Un Manager falso (eco TCP) en el contenedor `wazuh` y un cliente de prueba verifican el paso L4, el `allow/deny`, el log sin contenido, el pin de versión y logrotate.

**Tech Stack:** Ansible (ansible-core 2.21, colección `community.general`), NGINX 1.18 de Ubuntu 22.04, Python 3.10 stdlib, bash, GNU make, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-29-logrelay-role-design.md` (commit `de7402c`).

## Global Constraints

- Rama `practica/ansible-local`. Todo comando se corre desde `/home/tacosconchelas/Projects/SOC-TESIS/ansible` dentro de `nix-shell --run '...'`.
- Versión fijada de NGINX: `1.18.0-6ubuntu14.21` (`17_SOFTWARE_BASELINE.md`).
- IPs: relay `10.50.30.10`, Manager `10.50.40.10`, agente (honeyserver) `10.50.10.10`, `lab_cidr` `192.168.1.0/24`. Puertos 1514 y 1515, TCP.
- Contrato de tags (E1-8): `install` es el único que descarga; `config` no arranca servicios; `start` nunca descarga.
- UFW: entrada denegada, salida **permitida**; reglas `allow` antes de activar; solo con `when: ansible_virtualization_type != 'docker'` (E1-7).
- El relay no recibe secretos ni credenciales de Wazuh. No se escriben PSK, llaves ni contraseñas.
- Los cambios se limitan a `ansible/` y `docs/`. No tocar `terraform/`, `.knowledge/` ni `PIPELINE.md`.
- Gates por código de salida (nunca por texto en stdout). Mensajes en español.
- Sin dependencias nuevas salvo `community.general` (ya presente en el `nix-shell`).
- Commits en español, sin líneas de atribución.
- Todo el trabajo se verifica con `nix-shell`; los estados de contenedores se reinician con `make clean` antes de una corrida completa.

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `ansible/local/scripts/recap-check.sh` (mod) | Agrega el modo `ok` (sin fallos, `changed` libre) |
| `ansible/local/scripts/recap-check-selftest.sh` (nuevo) | Prueba los 3 modos de `recap-check.sh` con recaps sintéticos |
| `ansible/local/scripts/relay-probe.py` (nuevo) | Eco TCP (`serve`) y cliente (`probe`) del ensayo, fuera del rol |
| `ansible/local/scripts/relay-check.sh` (nuevo) | Los 5 checks del diseño §5 |
| `ansible/Makefile` (mod) | Targets `recap-check-selftest` y `relay-check`; `rehearse` arranca dos veces; `preflight` los incluye |
| `ansible/roles/logrelay/defaults/main.yml` (nuevo) | Variables `logrelay_*` |
| `ansible/roles/logrelay/templates/nginx.conf.j2` (nuevo) | `nginx.conf` mínimo con `stream` |
| `ansible/roles/logrelay/templates/soc-relay.logrotate.j2` (nuevo) | Rotación a 7 días |
| `ansible/roles/logrelay/handlers/main.yml` (nuevo) | Recarga de NGINX solo si está activo |
| `ansible/roles/logrelay/tasks/main.yml` (reemplaza el marcador) | Tareas `install`/`config`/`start` |
| `ansible/requirements.yml` (nuevo) | `community.general` para el controlador real |
| `ansible/local/README.md` (mod) | Sección de `relay-check` |
| `docs/superpowers/specs/2026-10-29-logrelay-role-design.md` (mod) | Refinamientos descubiertos al planear |

Decisiones de implementación que refinan la spec (se documentan en la Tarea 4):
1. Variables con prefijo `logrelay_` (lo exige `ansible-lint`, regla `var-naming[no-role-prefix]`).
2. Se retienen (`hold`) cuatro paquetes (`nginx`, `nginx-core`, `nginx-common`, `libnginx-mod-stream`): el binario `/usr/sbin/nginx` vive en `nginx-core`, no en el metapaquete `nginx`.
3. El log va a `/var/log/soc-relay/stream.log`: el paquete NGINX ya rota `/var/log/nginx/*.log` (14 días) y un segundo logrotate sobre el mismo archivo daría error de entrada duplicada.
4. `make rehearse` corre `--tags start` dos veces: arrancar NGINX es un cambio legítimo en la primera.

---

### Task 1: Modo `ok` en `recap-check.sh` y arranque en dos pasadas

**Files:**
- Create: `ansible/local/scripts/recap-check-selftest.sh`
- Modify: `ansible/local/scripts/recap-check.sh`
- Modify: `ansible/Makefile`

**Interfaces:**
- Produces: `recap-check.sh <log> ok|changed|nochange` (nuevo modo `ok`: exige `failed=0` y `unreachable=0`, `changed` libre); target `make recap-check-selftest`; `rehearse` con `start1.log` (modo `ok`) y `start2.log` (modo `nochange`).

- [ ] **Step 1: Escribir la prueba que falla**

Crear `ansible/local/scripts/recap-check-selftest.sh`:

```bash
#!/usr/bin/env bash
# Prueba recap-check.sh con recaps sinteticos: cada modo debe aceptar y rechazar.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# expect <rc_esperado> <modo> <changed> <failed> <unreachable>
expect() {
  printf 'PLAY RECAP *****\nhost1 : ok=3 changed=%s unreachable=%s failed=%s skipped=0 rescued=0 ignored=0\n' \
    "$3" "$5" "$4" >"$tmp/log"
  local rc=0
  bash "$here/recap-check.sh" "$tmp/log" "$2" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FALLA: modo=$2 changed=$3 failed=$4 unreachable=$5 -> rc=$rc, se esperaba $1" >&2
    exit 1
  fi
}

expect 0 ok 2 0 0
expect 0 ok 0 0 0
expect 1 ok 0 1 0
expect 1 ok 0 0 1
expect 0 changed 2 0 0
expect 1 changed 0 0 0
expect 0 nochange 0 0 0
expect 1 nochange 1 0 0
expect 2 bogus 0 0 0

echo "recap-check-selftest: ok (9 casos)"
```

- [ ] **Step 2: Ejecutar y comprobar que falla**

Run: `cd ~/Projects/SOC-TESIS/ansible && bash local/scripts/recap-check-selftest.sh; echo "rc=$?"`
Expected: `FALLA: modo=ok changed=2 failed=0 unreachable=0 -> rc=2, se esperaba 0` y `rc=1`.

- [ ] **Step 3: Implementar el modo `ok`**

En `ansible/local/scripts/recap-check.sh`, reemplazar el comentario de cabecera:

```bash
#   recap-check.sh <log> changed     -> exige changed > 0, failed=0, unreachable=0
#   recap-check.sh <log> nochange    -> exige changed = 0, failed=0, unreachable=0
```

por:

```bash
#   recap-check.sh <log> changed     -> exige changed > 0, failed=0, unreachable=0
#   recap-check.sh <log> nochange    -> exige changed = 0, failed=0, unreachable=0
#   recap-check.sh <log> ok          -> exige failed=0, unreachable=0 (changed libre)
```

Reemplazar las dos líneas de uso:

```bash
log="${1:?uso: recap-check.sh LOG changed|nochange}"
mode="${2:?uso: recap-check.sh LOG changed|nochange}"
```

por:

```bash
log="${1:?uso: recap-check.sh LOG changed|nochange|ok}"
mode="${2:?uso: recap-check.sh LOG changed|nochange|ok}"
```

Y en el `case "$mode" in`, insertar antes del caso `*)`:

```bash
  ok)
    ;;
```

- [ ] **Step 4: Ejecutar y comprobar que pasa**

Run: `bash local/scripts/recap-check-selftest.sh; echo "rc=$?"`
Expected: `recap-check-selftest: ok (9 casos)` y `rc=0`.

- [ ] **Step 5: Cablear el Makefile**

En `ansible/Makefile`:

1. En `.PHONY`, reemplazar la última línea de la lista, `        gate-apply stage1 clean`, por:

```make
        gate-apply stage1 recap-check-selftest relay-check clean
```

2. Agregar, justo antes del target `rehearse:`:

```make
recap-check-selftest:
	@bash "$(LOCAL)/scripts/recap-check-selftest.sh"

relay-check:
	@bash "$(LOCAL)/scripts/relay-check.sh"

```

3. En `rehearse`, reemplazar:

```make
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags start 2>&1 | tee "$(LOGS)/start.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/start.log" nochange
```

por:

```make
	@echo "== arranque, 1a pasada: arrancar servicios es un cambio legitimo =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags start 2>&1 | tee "$(LOGS)/start1.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/start1.log" ok
	@echo "== arranque, 2a pasada: idempotente =="
	@cd "$(ANSIBLE_DIR)" && ansible-playbook site.yml --tags start 2>&1 | tee "$(LOGS)/start2.log"
	@bash "$(LOCAL)/scripts/recap-check.sh" "$(LOGS)/start2.log" nochange
```

4. Reemplazar la línea de `preflight`:

```make
preflight: lint tags-contract secret-scan secret-scan-selftest rehearse
```

por:

```make
preflight: lint tags-contract secret-scan secret-scan-selftest recap-check-selftest rehearse
```

5. En `help`, agregar tras la línea de `rehearse`:

```make
	@echo "  make recap-check-selftest  prueba los modos de recap-check.sh"
	@echo "  make relay-check        verifica el rol logrelay (requiere make rehearse previo)"
```

- [ ] **Step 6: Verificar el cableado sin ejecutar contenedores**

Run:
```bash
nix-shell --run 'make recap-check-selftest; make -n rehearse | grep -c "tags start"'
```
Expected: `recap-check-selftest: ok (9 casos)` y la salida del conteo es `2`.

- [ ] **Step 7: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/local/scripts/recap-check.sh ansible/local/scripts/recap-check-selftest.sh ansible/Makefile
git commit -m "feat(ansible): modo ok en recap-check y arranque de servicios en dos pasadas" -m "Arrancar un servicio es un cambio legitimo en la primera pasada de --tags start; la segunda debe ser idempotente. recap-check gana el modo ok y un selftest de 9 casos."
```

---

### Task 2: Herramientas de `relay-check` (primero la prueba, en rojo)

**Files:**
- Create: `ansible/local/scripts/relay-probe.py`
- Create: `ansible/local/scripts/relay-check.sh`

**Interfaces:**
- Consumes: `make relay-check` (Task 1); contenedores `soc-local-{logrelay,wazuh,honeyserver,strongswan}`; variable `logrelay_nginx_version` en `ansible/roles/logrelay/defaults/main.yml` (la crea la Tarea 3).
- Produces: `relay-probe.py serve SEGUNDOS PUERTO...` y `relay-probe.py probe HOST PUERTO TOKEN echo|none`; `relay-check.sh` (exit 0 solo si pasan los 5 checks).

- [ ] **Step 1: Escribir `relay-probe.py`**

Crear `ansible/local/scripts/relay-probe.py`:

```python
#!/usr/bin/env python3
"""Utilidad del ensayo local de logrelay (no forma parte del rol).

  relay-probe.py serve SEGUNDOS PUERTO [PUERTO...]   eco TCP; sale solo tras SEGUNDOS
  relay-probe.py probe HOST PUERTO TOKEN echo|none   cliente; exit 0 si se cumple lo esperado
"""
from __future__ import annotations

import socket
import sys
import threading
import time


def serve(seconds: float, ports: list[int]) -> int:
    deadline = time.monotonic() + seconds

    def handle(conn: socket.socket) -> None:
        with conn:
            try:
                while data := conn.recv(4096):
                    conn.sendall(data)
            except OSError:
                pass

    def listen(port: int) -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(8)
        srv.settimeout(0.5)
        while time.monotonic() < deadline:
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            threading.Thread(target=handle, args=(conn,), daemon=True).start()
        srv.close()

    threads = [threading.Thread(target=listen, args=(p,)) for p in ports]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return 0


def probe(host: str, port: int, token: str, expect: str) -> int:
    want = token.encode()
    got = b""
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.settimeout(3)
            s.sendall(want)
            try:
                while len(got) < len(want):
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    got += chunk
            except (socket.timeout, ConnectionResetError):
                pass
    except OSError:
        got = b""  # rechazo o corte antes de responder: sin eco

    ok = got == want if expect == "echo" else got == b""
    print(f"probe {host}:{port} esperado={expect} recibido={len(got)}B -> {'ok' if ok else 'FALLA'}")
    return 0 if ok else 1


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else ""
    if cmd == "serve" and len(argv) >= 4:
        return serve(float(argv[2]), [int(p) for p in argv[3:]])
    if cmd == "probe" and len(argv) == 6 and argv[5] in ("echo", "none"):
        return probe(argv[2], int(argv[3]), argv[4], argv[5])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
```

- [ ] **Step 2: Escribir `relay-check.sh`**

Crear `ansible/local/scripts/relay-check.sh`:

```bash
#!/usr/bin/env bash
# Verifica el rol logrelay en el ensayo local (spec 2026-10-29-logrelay-role-design.md §5).
# Requiere los contenedores arriba y convergidos (make rehearse).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
probe="$here/relay-probe.py"
defaults="$here/../../roles/logrelay/defaults/main.yml"

relay=soc-local-logrelay
manager=soc-local-wazuh
agent=soc-local-honeyserver
other=soc-local-strongswan
relay_ip=10.50.30.10
token="relay-check-$(date +%s)-$$"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }

# Manager falso en wazuh: eco en 1514 y 1515; se apaga solo a los 90 s.
docker cp "$probe" "$manager:/tmp/relay-probe.py"
docker exec -d "$manager" python3 /tmp/relay-probe.py serve 90 1514 1515
# El corchete evita que el sh -c se mate a si mismo (su cmdline no casa con la regex).
cleanup() {
  docker exec "$manager" sh -c 'for p in /proc/[0-9]*; do grep -qa "relay-probe[.]py" "$p/cmdline" 2>/dev/null && kill "${p#/proc/}" 2>/dev/null; done; true' >/dev/null 2>&1 || true
}
trap cleanup EXIT
sleep 1

run_probe() { # contenedor puerto modo
  docker exec -i "$1" python3 - probe "$relay_ip" "$2" "$token" "$3" <"$probe"
}

# 1. Paso L4 desde el agente permitido.
for port in 1514 1515; do
  if run_probe "$agent" "$port" echo; then good "honeyserver -> relay:$port pasa al Manager"; else bad "honeyserver no llega al Manager por el relay:$port"; fi
done

# 2. Origen no permitido: sin eco.
for port in 1514 1515; do
  if run_probe "$other" "$port" none; then good "strongswan -> relay:$port bloqueado"; else bad "strongswan recibio eco por relay:$port (deny all no actua)"; fi
done

# 3. access_log: metadatos si, contenido no.
sleep 1
log="$(docker exec "$relay" cat /var/log/soc-relay/stream.log 2>/dev/null || true)"
if grep -Eq '^10\.50\.10\.10 \[[^]]+\] TCP 200 ' <<<"$log"; then good "log registra la sesion permitida (200)"; else bad "el log no registra la sesion 200 de 10.50.10.10"; fi
if grep -Eq '^10\.50\.20\.10 \[[^]]+\] TCP 403 ' <<<"$log"; then good "log registra la sesion denegada (403)"; else bad "el log no registra la sesion 403 de 10.50.20.10"; fi
if grep -q "$token" <<<"$log"; then bad "el log contiene el contenido de la sesion"; else good "el log no contiene el contenido"; fi

# 4. Config valida, versión fijada y paquetes retenidos.
want="$(sed -n 's/^logrelay_nginx_version: *"\([^"]*\)".*/\1/p' "$defaults")"
have="$(docker exec "$relay" dpkg-query -W -f='${Version}' nginx 2>/dev/null || true)"
if [ -n "$want" ] && [ "$want" = "$have" ]; then good "nginx $have (fijada)"; else bad "version de nginx '$have', se esperaba '$want'"; fi
if docker exec "$relay" nginx -t >/dev/null 2>&1; then good "nginx -t"; else bad "nginx -t falla"; fi
if docker exec "$relay" systemctl is-active --quiet nginx; then good "nginx activo"; else bad "nginx no esta activo"; fi
holds="$(docker exec "$relay" apt-mark showhold 2>/dev/null || true)"
owner="$(docker exec "$relay" dpkg -S /usr/sbin/nginx 2>/dev/null | cut -d: -f1 || true)"
for pkg in nginx nginx-core nginx-common libnginx-mod-stream; do
  if grep -qx "$pkg" <<<"$holds"; then good "$pkg retenido"; else bad "$pkg no esta retenido"; fi
done
if [ -n "$owner" ] && grep -qx "$owner" <<<"$holds"; then good "el dueño de /usr/sbin/nginx ($owner) esta retenido"; else bad "el dueño de /usr/sbin/nginx ('$owner') no esta retenido"; fi

# 5. logrotate valido.
if docker exec "$relay" logrotate -d /etc/logrotate.d/soc-relay >/dev/null 2>&1; then good "logrotate -d"; else bad "logrotate -d falla"; fi

if [ "$fail" -ne 0 ]; then
  echo "relay-check: FALLA" >&2
  exit 1
fi
echo "relay-check: ok"
```

- [ ] **Step 3: Comprobar que las herramientas funcionan solas (cliente y eco, sin relay)**

Levantar el entorno con los roles marcador actuales y probar el eco directo contra el Manager falso:

```bash
cd ~/Projects/SOC-TESIS/ansible
nix-shell --run 'make clean rehearse' 2>&1 | tail -5
docker cp local/scripts/relay-probe.py soc-local-wazuh:/tmp/relay-probe.py
docker exec -d soc-local-wazuh python3 /tmp/relay-probe.py serve 20 1514
sleep 1
docker exec -i soc-local-honeyserver python3 - probe 10.50.40.10 1514 hola echo < local/scripts/relay-probe.py; echo "rc=$?"
docker exec -i soc-local-honeyserver python3 - probe 10.50.40.10 1514 hola none < local/scripts/relay-probe.py; echo "rc=$?"
```
Expected: `rehearse: ok...`, luego `probe 10.50.40.10:1514 esperado=echo recibido=4B -> ok` con `rc=0`, y para `none` la línea `-> FALLA` con `rc=1` (hubo eco, así que "none" falla). Esto prueba que el cliente distingue ambos modos.

- [ ] **Step 4: Ejecutar `relay-check` y comprobar que FALLA (rojo)**

El rol sigue siendo el marcador, así que no hay NGINX:

Run: `nix-shell --run 'make relay-check'; echo "rc=$?"`
Expected: líneas `FALLA: honeyserver no llega al Manager por el relay:1514`, `FALLA: ... nginx -t falla`, y al final `relay-check: FALLA` con `rc=2` (make) — nunca `relay-check: ok`.

- [ ] **Step 5: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/local/scripts/relay-probe.py ansible/local/scripts/relay-check.sh
git commit -m "test(ansible): relay-check y sonda TCP para el rol logrelay (en rojo)" -m "Los 5 checks de la spec: paso L4, deny all, log sin contenido, version fijada y retencion, logrotate. Falla mientras el rol sea un marcador."
```

---

### Task 3: Implementar el rol `logrelay` (verde)

**Files:**
- Create: `ansible/roles/logrelay/defaults/main.yml`
- Create: `ansible/roles/logrelay/templates/nginx.conf.j2`
- Create: `ansible/roles/logrelay/templates/soc-relay.logrotate.j2`
- Create: `ansible/roles/logrelay/handlers/main.yml`
- Replace: `ansible/roles/logrelay/tasks/main.yml`
- Create: `ansible/requirements.yml`
- Modify: `ansible/Makefile` (`preflight` incluye `relay-check`)

**Interfaces:**
- Consumes: `relay-check.sh` espera `logrelay_nginx_version: "..."` con ese formato exacto en `defaults/main.yml`; el log en `/var/log/soc-relay/stream.log` con formato `IP [fecha] TCP status ...`; el archivo `/etc/logrotate.d/soc-relay`.
- Produces: rol con variables `logrelay_listen_ip`, `logrelay_manager_ip`, `logrelay_agent_ip`, `logrelay_admin_cidr`, `logrelay_nginx_version`, `logrelay_log_dir`, `logrelay_log_keep_days`; handler `Recargar nginx si esta activo`.

- [ ] **Step 1: Variables**

Crear `ansible/roles/logrelay/defaults/main.yml`:

```yaml
---
# Valores de D4 (.knowledge/18_DECISIONES_IMPLEMENTACION.md §2) y del baseline (doc 17).
logrelay_listen_ip: "10.50.30.10"
logrelay_manager_ip: "10.50.40.10"
logrelay_agent_ip: "10.50.10.10"
logrelay_admin_cidr: "192.168.1.0/24" # lab_cidr de terraform/lab
logrelay_nginx_version: "1.18.0-6ubuntu14.21"
logrelay_log_dir: /var/log/soc-relay
logrelay_log_keep_days: 7
```

- [ ] **Step 2: Plantilla de NGINX**

Crear `ansible/roles/logrelay/templates/nginx.conf.j2`:

```
# Gestionado por Ansible (rol logrelay). D4: NGINX stream L4, sin descifrar ni almacenar.
user www-data;
worker_processes auto;
pid /run/nginx.pid;
# libnginx-mod-stream instala aqui el load_module; sin esta linea no existe `stream`.
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
}

stream {
    log_format relay '$remote_addr [$time_local] $protocol $status $bytes_sent $bytes_received $session_time';
    access_log {{ logrelay_log_dir }}/stream.log relay;

    upstream manager_1514 {
        server {{ logrelay_manager_ip }}:1514;
    }
    upstream manager_1515 {
        server {{ logrelay_manager_ip }}:1515;
    }

    server {
        listen {{ logrelay_listen_ip }}:1514;
        allow {{ logrelay_agent_ip }};
        deny all;
        proxy_pass manager_1514;
    }

    server {
        listen {{ logrelay_listen_ip }}:1515;
        allow {{ logrelay_agent_ip }};
        deny all;
        proxy_pass manager_1515;
    }
}
```

- [ ] **Step 3: Plantilla de logrotate**

Crear `ansible/roles/logrelay/templates/soc-relay.logrotate.j2`:

```
{{ logrelay_log_dir }}/stream.log {
    daily
    rotate {{ logrelay_log_keep_days }}
    missingok
    notifempty
    compress
    delaycompress
    create 0640 www-data adm
    postrotate
        [ ! -f /run/nginx.pid ] || /usr/sbin/nginx -s reopen
    endscript
}
```

- [ ] **Step 4: Handler**

Crear `ansible/roles/logrelay/handlers/main.yml`:

```yaml
---
# policy-rc.d (rol common) bloquea invoke-rc.d, pero no systemctl: se usa systemctl.
- name: Recargar nginx si esta activo
  ansible.builtin.shell: |
    if systemctl is-active --quiet nginx; then systemctl reload nginx; fi
  changed_when: false
```

- [ ] **Step 5: Tareas**

Reemplazar todo el contenido de `ansible/roles/logrelay/tasks/main.yml` por:

```yaml
---
# Rol logrelay: NGINX stream L4 (D4). Agente Wazuh del honeyserver -> 1514/1515 -> Manager.
# Diseño: docs/superpowers/specs/2026-10-29-logrelay-role-design.md
- name: Instalar NGINX con stream, logrotate y ufw en la versión fijada
  ansible.builtin.apt:
    name:
      - "nginx={{ logrelay_nginx_version }}"
      - "nginx-core={{ logrelay_nginx_version }}"
      - "nginx-common={{ logrelay_nginx_version }}"
      - "libnginx-mod-stream={{ logrelay_nginx_version }}"
      - logrotate
      - ufw
    state: present
    update_cache: true
    cache_valid_time: 3600
  tags: [install]

- name: Retener los paquetes de NGINX en la versión fijada
  ansible.builtin.dpkg_selections:
    name: "{{ item }}"
    selection: hold
  loop:
    - nginx
    - nginx-core
    - nginx-common
    - libnginx-mod-stream
  tags: [install]

- name: Crear el directorio de logs del relay
  ansible.builtin.file:
    path: "{{ logrelay_log_dir }}"
    state: directory
    owner: root
    group: adm
    mode: "0750"
  tags: [config]

- name: Escribir nginx.conf (solo stream, validado con nginx -t)
  ansible.builtin.template:
    src: nginx.conf.j2
    dest: /etc/nginx/nginx.conf
    owner: root
    group: root
    mode: "0644"
    validate: /usr/sbin/nginx -t -c %s
  notify: Recargar nginx si esta activo
  tags: [config]

- name: Escribir la rotación de logs del relay
  ansible.builtin.template:
    src: soc-relay.logrotate.j2
    dest: /etc/logrotate.d/soc-relay
    owner: root
    group: root
    mode: "0644"
  tags: [config]

# UFW solo en host real (E1-7): en contenedor cortaria el SSH del ensayo.
# Orden: reglas allow -> politicas -> activar (la salida queda permitida; el
# egreso lo controla el NSG, cerrado fuera de la ventana de mantenimiento).
- name: Permitir SSH desde la LAN del laboratorio (solo host real)
  community.general.ufw:
    rule: allow
    port: "22"
    proto: tcp
    src: "{{ logrelay_admin_cidr }}"
  when: ansible_virtualization_type != 'docker'
  tags: [config]

- name: Permitir 1514 y 1515 solo desde el agente del honeyserver (solo host real)
  community.general.ufw:
    rule: allow
    port: "{{ item }}"
    proto: tcp
    src: "{{ logrelay_agent_ip }}"
  loop: ["1514", "1515"]
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

- name: Habilitar y arrancar NGINX
  ansible.builtin.systemd_service:
    name: nginx
    enabled: true
    state: started
  tags: [start]
```

- [ ] **Step 6: Colección para el controlador real**

Crear `ansible/requirements.yml`:

```yaml
---
# El controlador real (192.168.1.73) necesita esta coleccion para community.general.ufw.
# En el nix-shell local ya viene con el paquete `ansible`.
collections:
  - name: community.general
```

- [ ] **Step 7: Incluir `relay-check` en el preflight**

En `ansible/Makefile`, reemplazar:

```make
preflight: lint tags-contract secret-scan secret-scan-selftest recap-check-selftest rehearse
```

por:

```make
preflight: lint tags-contract secret-scan secret-scan-selftest recap-check-selftest rehearse relay-check
```

- [ ] **Step 8: Lint y contrato de tags**

Run: `cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'make ansible-lint syntax-check tags-contract'`
Expected: `Passed: 0 failure(s), 0 warning(s)`, `tags-contract: ok (5 archivos de tareas)` y sin errores. Si `ansible-lint` marca algo, corregir la causa en el rol (no desactivar la regla).

- [ ] **Step 9: Corrida completa desde estado limpio**

Run: `nix-shell --run 'make clean preflight' 2>&1 | tail -40; echo "rc=${PIPESTATUS[0]}"`
Expected, en orden:
- `recap-check-selftest: ok (9 casos)`
- 1ª pasada `recap-check: ok (changed) ...`, 2ª `recap-check: ok (nochange) changed=0 ...`, `--check --diff` con `nochange`
- arranque 1ª pasada `recap-check: ok (ok) ...` y 2ª `recap-check: ok (nochange) changed=0 ...`
- `netcheck: egreso cerrado en los 4 contenedores`
- todos los `ok:` de `relay-check` (pasa 1514 y 1515, strongswan bloqueado, log 200 y 403, sin contenido, nginx fijado, `nginx -t`, activo, 4 retenidos, dueño retenido, `logrotate -d`) y `relay-check: ok`
- `rc=0`

Si el paso de instalación falla con `version ... not found`, ver `docker exec soc-local-logrelay apt-cache madison nginx` y reportar (es el riesgo "Ubuntu retiró la versión" de la spec §4: no se cambia la versión sin re-verificar el baseline).

- [ ] **Step 10: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/roles/logrelay ansible/requirements.yml ansible/Makefile
git commit -m "feat(ansible): rol logrelay con NGINX stream L4 (D4)" -m "Plantilla de nginx.conf solo con stream y allow/deny, version fijada y retenida (nginx, nginx-core, nginx-common, libnginx-mod-stream), log de metadatos con rotacion a 7 dias y UFW solo en host real. relay-check entra al preflight."
```

---

### Task 4: Documentación y refinamientos de la spec

**Files:**
- Modify: `ansible/local/README.md`
- Modify: `docs/superpowers/specs/2026-10-29-logrelay-role-design.md`

- [ ] **Step 1: Documentar `relay-check` en el README local**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS/ansible
cat >> local/README.md <<'EOF'

## Rol logrelay: `make relay-check`

Verifica el rol `logrelay` (NGINX `stream`, D4) sobre los contenedores ya convergidos, por lo que se corre **después** de `make rehearse` (o dentro de `make preflight`, que ya lo incluye).

Qué hace: levanta un Manager falso (eco TCP) en el contenedor `wazuh` y comprueba (1) que `honeyserver` llega por el relay a 1514 y 1515, (2) que `strongswan` queda bloqueado por `deny all`, (3) que el log `/var/log/soc-relay/stream.log` registra las sesiones (200/403) sin su contenido, (4) `nginx -t`, versión fijada y los paquetes retenidos, (5) `logrotate -d`.

Qué NO valida: reglas y activación reales de UFW (en contenedor se omiten), el NSG de Azure y el protocolo real del agente Wazuh (enrolamiento TLS en 1515, cifrado en 1514). Eso se verifica en el primer ciclo real y en la Etapa 9 de `PIPELINE.md`.

`make rehearse` arranca los servicios dos veces: la 1ª pasada de `--tags start` puede cambiar cosas (arrancar NGINX es un cambio legítimo) y la 2ª debe dar `changed=0`.
EOF
```

- [ ] **Step 2: Parchar la spec con los refinamientos**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS
python3 - <<'EOF'
import pathlib
p = pathlib.Path("docs/superpowers/specs/2026-10-29-logrelay-role-design.md")
s = p.read_text()

def rep(old, new, count=1):
    global s
    assert s.count(old) == count, (old, s.count(old))
    s = s.replace(old, new)

# 1. Prefijo de rol exigido por ansible-lint (var-naming[no-role-prefix]).
n = s.count("`relay_")
assert n >= 5, n
s = s.replace("`relay_", "`logrelay_")

# 2. Se retienen los cuatro paquetes: el binario vive en nginx-core.
rep("`nginx` y `libnginx-mod-stream` en la versión exacta, `apt-mark hold`, `ufw` si falta",
    "`nginx`, `nginx-core`, `nginx-common` y `libnginx-mod-stream` en la versión exacta y retenidos (`dpkg_selections` hold; el binario `/usr/sbin/nginx` vive en `nginx-core`), `ufw` y `logrotate` si faltan")

# 3. Log fuera de /var/log/nginx para no chocar con el logrotate del paquete.
rep("logrotate a 7 días; reglas UFW",
    "logs en `/var/log/soc-relay/stream.log` (fuera de `/var/log/nginx/`, que el paquete ya rota a 14 días) con logrotate propio a 7 días; reglas UFW")

# 4. Check 4 con los cuatro paquetes y el dueño del binario.
rep("`apt-mark showhold` incluye `nginx` y `libnginx-mod-stream`.",
    "`apt-mark showhold` incluye los cuatro paquetes y el dueño de `/usr/sbin/nginx`.")

# 5. El arranque de NGINX es un cambio real: rehearse arranca dos veces.
rep("siguen cubriendo idempotencia y que `start` no descargue.",
    "siguen cubriendo idempotencia y que `start` no descargue. Como arrancar NGINX es un cambio legítimo, `make rehearse` corre `--tags start` dos veces: la primera exige solo ausencia de fallos (`recap-check.sh ... ok`) y la segunda `changed=0`.")

p.write_text(s)
print("spec parchada")
EOF
git diff --stat
```
Expected: `spec parchada` y un diff en la spec y en `ansible/local/README.md`.

- [ ] **Step 3: Escaneo de secretos y commit**

```bash
cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'make secret-scan'
cd .. && git add ansible/local/README.md docs/superpowers/specs/2026-10-29-logrelay-role-design.md
git commit -m "docs(ansible): relay-check y refinamientos de la spec del rol logrelay" -m "Prefijo logrelay_ en variables, retencion de cuatro paquetes, log fuera de /var/log/nginx y arranque en dos pasadas."
```
Expected: `secret-scan: ok (...)` y el commit creado.

---

## Self-Review

**Cobertura de la spec:**
- §1 Objetivo y relay sin credenciales → Tarea 3 (plantilla sin secretos). ✔
- §2 Enfoque (plantilla Jinja, variables en defaults, `nginx.conf` mínimo) → Tarea 3, pasos 1-2. ✔
- §3 Tags `install`/`config`/`start` → Tarea 3, paso 5; UFW con `when` y orden allow→políticas→enable. ✔
- §3 `allow`/`deny` en NGINX → plantilla. ✔
- §4 Errores: versión retirada (nota del paso 9), plantilla inválida (`validate`), arranque automático (policy-rc.d de `common`, sin cambios), recarga solo si activo (handler), UFW (orden), install sin egreso (la ventana ya lo exige). ✔
- §5 Pruebas: los 5 checks → Tarea 2 (`relay-check.sh`), en `preflight` en Tarea 3. ✔
- §6 Criterio de listo → Tarea 3 paso 9 (`make clean preflight`, `rc=0`). ✔
- §7 Fuera de alcance: no se toca Wazuh, agente, Terraform. ✔

**Escaneo de placeholders:** sin TBD/TODO; todos los pasos de código muestran el código completo.

**Consistencia de nombres:** `logrelay_nginx_version` (defaults) ↔ `sed` de `relay-check.sh`; `/var/log/soc-relay/stream.log` ↔ `logrelay_log_dir` y los `grep` de `relay-check.sh`; `/etc/logrotate.d/soc-relay` ↔ plantilla de logrotate y `logrotate -d`; handler `Recargar nginx si esta activo` ↔ `notify`; `recap-check.sh ... ok` ↔ `start1.log`.

**Riesgos conocidos no verificables localmente:** las tareas de UFW (solo host real) se validan solo con lint y sintaxis; se ejercitan por primera vez en el ciclo real (Etapa 6, justo antes de `ansible all -m ping`).
