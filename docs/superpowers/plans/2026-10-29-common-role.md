# Rol `common` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ampliar el rol `common` con tres bloques (sin actualizaciones automáticas, hora UTC verificada, sshd endurecido) y probarlo en los contenedores locales con `make common-check`.

**Architecture:** Mismo rol `common` con tareas nuevas etiquetadas `config`/`start` (E1-8), un handler `reload` de sshd y variables `common_*`. El entorno de ensayo cambia en dos puntos para que los checks no pasen en vacío: el `sshd` de los contenedores deja de traer el endurecimiento (y gana el `Include` de `sshd_config.d`) y los contenedores nacen en `America/Mexico_City`.

**Tech Stack:** Ansible (ansible-core 2.21), Ubuntu 22.04 (contenedor systemd), bash, GNU make, Docker Compose.

**Spec:** `docs/superpowers/specs/2026-10-29-common-role-design.md` (commit `8e5b206`).

## Global Constraints

- Rama `practica/ansible-local`. Todo comando se corre desde `/home/tacosconchelas/Projects/SOC-TESIS/ansible` dentro de `nix-shell --run '...'`.
- Contrato de tags (E1-8): `install` es el único que descarga; `config` no arranca servicios de la aplicación; `start` nunca descarga.
- E1-7: las tareas no aplicables en contenedor llevan `when: ansible_virtualization_type != 'docker'`.
- Drop-in de sshd: `/etc/ssh/sshd_config.d/20-soc-hardening.conf`, sin `Port` (no debe pisar el `10-admin-port.conf` de honeyserver, E1-2). Valores: `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `MaxAuthTries 3`. Se valida con `sshd -t -f %s`; se aplica con `reload`, nunca `restart`.
- Actualizaciones automáticas: `/etc/apt/apt.conf.d/99-soc-no-auto.conf` con `APT::Periodic::Update-Package-Lists "0";`, `APT::Periodic::Unattended-Upgrade "0";`, `APT::Periodic::Download-Upgradeable-Packages "0";`; timers `apt-daily.timer` y `apt-daily-upgrade.timer` detenidos, deshabilitados y enmascarados; estas tareas van **antes** del `apt` en el archivo.
- Hora: zona `UTC`; en `start`, solo host real, `NTPSynchronized` debe valer `yes` (12 reintentos de 10 s) o el play falla.
- La tarea `apt` de `common` agrega `lock_timeout: 120`.
- Variables con prefijo `common_` (regla `var-naming[no-role-prefix]` de `ansible-lint`).
- No se agregan paquetes nuevos al rol. No se escriben PSK, llaves ni contraseñas.
- Los cambios se limitan a `ansible/` y `docs/`. No tocar `terraform/` ni `.knowledge/`.
- Gates por código de salida (nunca por texto en stdout). Mensajes en español.
- Commits en español, sin líneas de atribución.
- No debilitar ningún check ni regla de lint para lograr verde.
- Una corrida completa se hace con `make clean preflight` (con contenedores ya convergidos, la 1ª pasada falla por falta de cambios). Tarda más de 10 minutos: correrla en segundo plano con la salida a un archivo.

## File Structure

| Archivo | Responsabilidad |
|---|---|
| `ansible/local/sshd_config.tpl` (mod) | `Include` de `sshd_config.d`; sin los 3 valores de endurecimiento |
| `ansible/local/Dockerfile` (mod) | `tzdata` y zona inicial `America/Mexico_City` |
| `ansible/local/scripts/common-check.sh` (nuevo) | Los 5 checks del diseño §4 |
| `ansible/Makefile` (mod) | Target `common-check`; `preflight` lo incluye |
| `ansible/roles/common/defaults/main.yml` (nuevo) | Variables `common_*` |
| `ansible/roles/common/handlers/main.yml` (nuevo) | `Recargar sshd` |
| `ansible/roles/common/tasks/main.yml` (reemplaza) | Tareas existentes + 3 bloques nuevos |
| `ansible/PIPELINE.md` (mod) | Fila de hora en la Etapa 8 |
| `ansible/local/README.md` (mod) | Sección de `common-check` |
| `docs/superpowers/specs/2026-10-29-common-role-design.md` (mod) | Refinamientos al implementar |

Decisión de implementación que refina la spec: la zona horaria se fija con `file` (enlace `/etc/localtime`) y `copy` (`/etc/timezone`), no con `community.general.timezone`. Es lo que hace `timedatectl set-timezone` pero sin depender de dbus, así que es idéntico en contenedor y en host real.

Paralelismo: la Tarea 3 (documentación) solo toca `PIPELINE.md`, `ansible/local/README.md` y la spec; es independiente de la Tarea 2 y puede ejecutarse a la vez. Al commitear, si `git` reporta `index.lock`, esperar unos segundos y reintentar.

---

### Task 1: Entorno de ensayo y `common-check` (primero la prueba, en rojo)

**Files:**
- Modify: `ansible/local/sshd_config.tpl`
- Modify: `ansible/local/Dockerfile`
- Create: `ansible/local/scripts/common-check.sh`
- Modify: `ansible/Makefile`

**Interfaces:**
- Produces: `make common-check` (exit 0 solo si pasan los 5 checks en las 4 VMs); el entorno local parte sin endurecimiento de sshd y con zona `America/Mexico_City`.

- [ ] **Step 1: Quitar el endurecimiento de la plantilla de sshd y añadir el `Include`**

Reemplazar todo el contenido de `ansible/local/sshd_config.tpl` por:

```
# Plantilla de sshd para el laboratorio local. `__PORT__` lo sustituye el
# entrypoint con SSHD_PORT (22 salvo honeyserver, que usa 22222).
# Igual que Ubuntu 22.04: los drop-ins de sshd_config.d van primero y "el primer
# valor gana". El endurecimiento (PermitRootLogin, PasswordAuthentication,
# KbdInteractiveAuthentication, MaxAuthTries) lo aporta el rol `common`; si
# estuviera aqui, los checks de common-check pasarian aunque el rol no hiciera nada.
Include /etc/ssh/sshd_config.d/*.conf

Port __PORT__
AddressFamily any
ListenAddress 0.0.0.0

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes

X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server
```

- [ ] **Step 2: Contenedores en otra zona horaria**

En `ansible/local/Dockerfile`, dentro del `apt-get install`, reemplazar la línea:

```
      sudo \
```

por:

```
      sudo \
      tzdata \
```

y justo después del bloque `RUN useradd ... && chmod 0440 /etc/sudoers.d/90-soctesis`, agregar:

```
# Zona inicial distinta de UTC: el contenedor ya nace en UTC, asi que sin esto el
# check de zona horaria pasaria aunque el rol common no hiciera nada.
RUN ln -sf /usr/share/zoneinfo/America/Mexico_City /etc/localtime \
 && echo America/Mexico_City > /etc/timezone
```

- [ ] **Step 3: Escribir `common-check.sh`**

Crear `ansible/local/scripts/common-check.sh`:

```bash
#!/usr/bin/env bash
# Verifica el rol common en el ensayo local (spec 2026-10-29-common-role-design.md §4).
# Requiere los contenedores arriba y convergidos (make rehearse).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
local_dir="$(cd "$here/.." && pwd)"
known="$local_dir/.known_hosts"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }

# nombre contenedor ip puerto
vms=(
  "strongswan soc-local-strongswan 10.50.20.10 22"
  "wazuh soc-local-wazuh 10.50.40.10 22"
  "logrelay soc-local-logrelay 10.50.30.10 22"
  "honeyserver soc-local-honeyserver 10.50.10.10 22222"
)

for entry in "${vms[@]}"; do
  read -r name ctr ip port <<<"$entry"

  # 1. Timers de apt enmascarados e inactivos.
  for t in apt-daily.timer apt-daily-upgrade.timer; do
    state="$(docker exec "$ctr" systemctl is-enabled "$t" 2>/dev/null || true)"
    if [ "$state" = masked ] && ! docker exec "$ctr" systemctl is-active --quiet "$t"; then
      good "$name: $t enmascarado e inactivo"
    else
      bad "$name: $t no esta enmascarado/inactivo (is-enabled='$state')"
    fi
  done

  # 2. apt sin periodos automaticos. La imagen de contenedor ya desactiva el
  # periodo, asi que solo el archivo del rol prueba que el rol actuo.
  conf=/etc/apt/apt.conf.d/99-soc-no-auto.conf
  if docker exec "$ctr" grep -qx 'APT::Periodic::Unattended-Upgrade "0";' "$conf" 2>/dev/null \
     && docker exec "$ctr" grep -qx 'APT::Periodic::Update-Package-Lists "0";' "$conf" 2>/dev/null \
     && docker exec "$ctr" grep -qx 'APT::Periodic::Download-Upgradeable-Packages "0";' "$conf" 2>/dev/null; then
    good "$name: $conf con las 3 lineas"
  else
    bad "$name: falta $conf o no tiene las 3 lineas"
  fi
  dump="$(docker exec "$ctr" apt-config dump 2>/dev/null || true)"
  if grep -q '^APT::Periodic::Unattended-Upgrade "0";' <<<"$dump" \
     && grep -q '^APT::Periodic::Update-Package-Lists "0";' <<<"$dump"; then
    good "$name: apt-config dump sin actualizacion automatica"
  else
    bad "$name: apt-config dump aun permite actualizacion automatica"
  fi

  # 3. Configuracion efectiva de sshd.
  eff="$(docker exec "$ctr" /usr/sbin/sshd -T 2>/dev/null || true)"
  for want in "permitrootlogin no" "passwordauthentication no" \
              "kbdinteractiveauthentication no" "maxauthtries 3" "port $port"; do
    if grep -qx "$want" <<<"$eff"; then good "$name: sshd -T '$want'"; else bad "$name: sshd -T no tiene '$want'"; fi
  done

  # 4. El demonio EN EJECUCION ya no ofrece contrasena ni teclado interactivo.
  out="$(ssh -o BatchMode=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known" -o GlobalKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -p "$port" "soctesis@$ip" true 2>&1 || true)"
  if grep -Fq 'Permission denied (publickey)' <<<"$out"; then
    good "$name: el demonio solo ofrece publickey"
  else
    bad "$name: el demonio ofrece mas que publickey (salida: $out)"
  fi

  # 5. Zona horaria.
  tz="$(docker exec "$ctr" timedatectl show -p Timezone --value 2>/dev/null || true)"
  if [ "$tz" = UTC ]; then good "$name: zona horaria UTC"; else bad "$name: zona horaria '$tz', se esperaba UTC"; fi
done

if [ "$fail" -ne 0 ]; then
  echo "common-check: FALLA" >&2
  exit 1
fi
echo "common-check: ok"
```

- [ ] **Step 4: Cablear el Makefile (sin incluirlo aún en `preflight`)**

En `ansible/Makefile`:

1. En `.PHONY`, reemplazar la última línea `        gate-apply stage1 recap-check-selftest relay-check clean` por:

```make
        gate-apply stage1 recap-check-selftest relay-check common-check clean
```

2. Justo después del target `relay-check:` (su receta `@bash "$(LOCAL)/scripts/relay-check.sh"`), agregar:

```make

common-check:
	@bash "$(LOCAL)/scripts/common-check.sh"
```

3. En `help`, tras la línea de `relay-check`, agregar:

```make
	@echo "  make common-check       verifica el rol common (requiere make rehearse previo)"
```

- [ ] **Step 5: Lint estático de los scripts**

Run: `cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'shellcheck local/scripts/common-check.sh && make -n common-check'`
Expected: sin salida de shellcheck y `bash ".../common-check.sh"` impreso por `make -n`.

- [ ] **Step 6: Levantar el entorno con el rol `common` aún sin cambios**

Run: `nix-shell --run 'make clean rehearse' > /tmp/claude-1000/-home-tacosconchelas-Projects-SOC-TESIS/184cc9c6-ced0-48b4-8367-768cc61da65d/scratchpad/rehearse-t1.log 2>&1; echo "rc=$?"`
(En segundo plano si hace falta; puede tardar varios minutos.)
Expected: `rc=0` y `rehearse: ok` en el log. El `sshd` sin endurecimiento no impide a Ansible entrar (usa llave).

- [ ] **Step 7: Ejecutar `common-check` y comprobar que FALLA (rojo)**

Run: `nix-shell --run 'make common-check'; echo "rc=$?"`
Expected: líneas `FALLA:` para los timers (`is-enabled='...'` distinto de `masked`), `99-soc-no-auto.conf`, `sshd -T no tiene 'passwordauthentication no'`, `el demonio ofrece mas que publickey` y `zona horaria 'America/Mexico_City'`; termina con `common-check: FALLA` y `rc=2` (make). Nunca `common-check: ok`.

- [ ] **Step 8: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/local/sshd_config.tpl ansible/local/Dockerfile ansible/local/scripts/common-check.sh ansible/Makefile
git commit -m "test(ansible): common-check y entorno de ensayo sin endurecimiento (en rojo)" -m "El sshd local pierde el endurecimiento y gana el Include de sshd_config.d; los contenedores nacen en America/Mexico_City. common-check falla mientras el rol no haga nada."
```

---

### Task 2: Implementar el rol `common` (verde)

**Files:**
- Create: `ansible/roles/common/defaults/main.yml`
- Create: `ansible/roles/common/handlers/main.yml`
- Replace: `ansible/roles/common/tasks/main.yml`
- Modify: `ansible/Makefile` (`preflight` incluye `common-check`)

**Interfaces:**
- Consumes: `common-check.sh` espera el archivo `/etc/apt/apt.conf.d/99-soc-no-auto.conf` con las 3 líneas exactas, timers `masked`, `sshd -T` con los valores y `timedatectl show -p Timezone --value` = `UTC`.
- Produces: variables `common_timezone`, `common_ssh_max_auth_tries`, `common_ntp_retries`, `common_ntp_delay`; handler `Recargar sshd`.

- [ ] **Step 1: Variables**

Crear `ansible/roles/common/defaults/main.yml`:

```yaml
---
# Rol common. Diseño: docs/superpowers/specs/2026-10-29-common-role-design.md
common_timezone: "UTC"
common_ssh_max_auth_tries: 3
common_ntp_retries: 12
common_ntp_delay: 10
```

- [ ] **Step 2: Handler**

Crear `ansible/roles/common/handlers/main.yml`:

```yaml
---
# reload y no restart: no corta la sesion de Ansible (spec §3).
- name: Recargar sshd
  ansible.builtin.systemd_service:
    name: ssh
    state: reloaded
```

- [ ] **Step 3: Tareas**

Reemplazar todo el contenido de `ansible/roles/common/tasks/main.yml` por:

```yaml
---
# Tareas base de las 4 VMs. Contrato de tags (ADR-006 E1-8).
# Diseño: docs/superpowers/specs/2026-10-29-common-role-design.md

# --- Sin actualizaciones automáticas ---------------------------------------
# Van primero: que ninguna actualización de arranque retenga el candado de dpkg
# cuando corra la tarea apt de más abajo.
- name: Desactivar la actualización automática de apt
  ansible.builtin.copy:
    dest: /etc/apt/apt.conf.d/99-soc-no-auto.conf
    content: |
      APT::Periodic::Update-Package-Lists "0";
      APT::Periodic::Unattended-Upgrade "0";
      APT::Periodic::Download-Upgradeable-Packages "0";
    owner: root
    group: root
    mode: "0644"
  tags: [config]

- name: Detener y enmascarar los timers de apt
  ansible.builtin.systemd_service:
    name: "{{ item }}"
    state: stopped
    enabled: false
    masked: true
  loop:
    - apt-daily.timer
    - apt-daily-upgrade.timer
  tags: [config]

# --- Paquetes base y bloqueo de arranque (E1-3) ------------------------------
- name: Instalar paquetes base
  ansible.builtin.apt:
    name:
      - ca-certificates
      - curl
    state: present
    update_cache: true
    cache_valid_time: 3600
    lock_timeout: 120
  tags: [install]

- name: Bloquear el arranque automático de servicios durante la instalación
  ansible.builtin.copy:
    dest: /usr/sbin/policy-rc.d
    content: |
      #!/bin/sh
      # ADR-006 E1-3: ningún servicio arranca solo durante la ventana de egreso.
      exit 101
    mode: "0755"
  tags: [install]

# --- Hora ----------------------------------------------------------------------
# Equivale a `timedatectl set-timezone` sin depender de dbus (igual en contenedor y host real).
- name: Fijar la zona horaria (enlace de /etc/localtime)
  ansible.builtin.file:
    src: "/usr/share/zoneinfo/{{ common_timezone }}"
    dest: /etc/localtime
    state: link
    force: true
  tags: [config]

- name: Fijar la zona horaria (/etc/timezone)
  ansible.builtin.copy:
    dest: /etc/timezone
    content: "{{ common_timezone }}\n"
    owner: root
    group: root
    mode: "0644"
  tags: [config]

# --- sshd endurecido ---------------------------------------------------------------
- name: Asegurar el directorio de drop-ins de sshd
  ansible.builtin.file:
    path: /etc/ssh/sshd_config.d
    state: directory
    owner: root
    group: root
    mode: "0755"
  tags: [config]

- name: Endurecer sshd con un drop-in (sin Port: no pisa el 22222 de honeyserver)
  ansible.builtin.copy:
    dest: /etc/ssh/sshd_config.d/20-soc-hardening.conf
    content: |
      PermitRootLogin no
      PasswordAuthentication no
      KbdInteractiveAuthentication no
      MaxAuthTries {{ common_ssh_max_auth_tries }}
    owner: root
    group: root
    mode: "0644"
    validate: /usr/sbin/sshd -t -f %s
  notify: Recargar sshd
  tags: [config]

- name: Leer la configuración efectiva de sshd
  ansible.builtin.command: /usr/sbin/sshd -T
  register: common_sshd_effective
  changed_when: false
  check_mode: false
  tags: [config]

- name: Comprobar los valores efectivos de sshd
  ansible.builtin.assert:
    that:
      - "'permitrootlogin no' in common_sshd_effective.stdout_lines"
      - "'passwordauthentication no' in common_sshd_effective.stdout_lines"
      - "'kbdinteractiveauthentication no' in common_sshd_effective.stdout_lines"
      - "('maxauthtries ' ~ common_ssh_max_auth_tries) in common_sshd_effective.stdout_lines"
    fail_msg: >-
      sshd -T no refleja el endurecimiento; otro archivo anterior de
      /etc/ssh/sshd_config.d (10-*) gana por "el primer valor gana".
  tags: [config]

- name: Crear el directorio de marcadores
  ansible.builtin.file:
    path: /etc/soc-tesis
    state: directory
    mode: "0755"
  tags: [config]

- name: Escribir el marcador del rol common
  ansible.builtin.copy:
    dest: /etc/soc-tesis/common
    content: "role=common\n"
    mode: "0644"
  tags: [config]

# --- Hora sincronizada (solo host real, solo lectura) -------------------------------
- name: Exigir la hora sincronizada (solo host real)
  ansible.builtin.command: timedatectl show -p NTPSynchronized --value
  register: common_ntp
  until: common_ntp.stdout == "yes"
  retries: "{{ common_ntp_retries }}"
  delay: "{{ common_ntp_delay }}"
  changed_when: false
  check_mode: false
  when: ansible_virtualization_type != 'docker'
  tags: [start]
```

- [ ] **Step 4: Incluir `common-check` en el preflight**

En `ansible/Makefile`, reemplazar:

```make
preflight: lint tags-contract secret-scan secret-scan-selftest recap-check-selftest rehearse relay-check
```

por:

```make
preflight: lint tags-contract secret-scan secret-scan-selftest recap-check-selftest rehearse relay-check common-check
```

- [ ] **Step 5: Lint, sintaxis y contrato de tags**

Run: `cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'make ansible-lint syntax-check tags-contract'`
Expected: `Passed: 0 failure(s), 0 warning(s)` (puede aparecer el ruido no fatal `ArgsRule ... File name too long` ya conocido), `tags-contract: ok (5 archivos de tareas)` y sin errores. Si `ansible-lint` marca algo, corregir la causa en el rol; no desactivar la regla.

- [ ] **Step 6: Corrida completa desde estado limpio**

Run (en segundo plano, salida a archivo): `nix-shell --run 'make clean preflight'`
Expected, en orden: `recap-check-selftest: ok (9 casos)`; 1ª pasada `recap-check: ok (changed)`; 2ª `ok (nochange) changed=0` (incluye que el handler de sshd no se dispare dos veces); `--check --diff` con `nochange`; arranque 1ª `ok` y 2ª `nochange changed=0`; `netcheck: egreso cerrado en los 4 contenedores`; todos los `ok:` de `relay-check` y `relay-check: ok`; todos los `ok:` de `common-check` para las 4 VMs y `common-check: ok`; `rc=0`.

Puntos de fallo conocidos (resolver la causa, no los checks):
- Si `systemd_service` falla al enmascarar un timer en el contenedor, ver `docker exec soc-local-wazuh systemctl status apt-daily.timer` y ajustar los parámetros (`enabled`/`masked`).
- Si el handler `Recargar sshd` falla, comprobar con `docker exec soc-local-wazuh systemctl status ssh` (la unidad se llama `ssh`).
- Si el check 4 del `common-check` ve `(publickey,password)`, el `reload` no llegó al demonio: revisar el handler.

- [ ] **Step 7: Commit**

```bash
cd ~/Projects/SOC-TESIS
git add ansible/roles/common ansible/Makefile
git commit -m "feat(ansible): rol common sin auto-updates, UTC verificada y sshd endurecido" -m "Timers apt-daily enmascarados y APT::Periodic en 0 antes del apt, zona horaria UTC por enlace (sin dbus), drop-in de sshd validado con sshd -t, reload por handler y assert de sshd -T, y NTPSynchronized exigido en start solo en host real. common-check entra al preflight."
```

---

### Task 3: Documentación y refinamientos de la spec (independiente de la Tarea 2)

**Files:**
- Modify: `ansible/PIPELINE.md`
- Modify: `ansible/local/README.md`
- Modify: `docs/superpowers/specs/2026-10-29-common-role-design.md`

- [ ] **Step 1: Fila de hora en la Etapa 8 de `PIPELINE.md`**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS
python3 - <<'EOF'
import pathlib
p = pathlib.Path("ansible/PIPELINE.md")
lines = p.read_text().split("\n")
idx = [i for i, l in enumerate(lines) if l.startswith("| Honeypot |")]
assert len(idx) == 1, idx
row = ("| Hora (4 VMs) | `timedatectl show -p NTPSynchronized --value` = `yes`; el rol `common` lo exige "
       "en el tag `start` (12 reintentos de 10 s) y falla si no llega. Depende de que la imagen sincronice "
       "sin egreso (PTP de Hyper-V); si no, decidir aquí si se configura chrony |")
lines.insert(idx[0] + 1, row)
p.write_text("\n".join(lines))
print("PIPELINE.md actualizado")
EOF
git diff --stat ansible/PIPELINE.md
```
Expected: `PIPELINE.md actualizado` y 1 línea agregada.

- [ ] **Step 2: Sección de `common-check` en el README local**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS/ansible
cat >> local/README.md <<'EOF'

## Rol common: `make common-check`

Verifica el rol `common` en las 4 VMs sobre los contenedores ya convergidos, por lo que se corre **después** de `make rehearse` (o dentro de `make preflight`, que ya lo incluye).

Qué comprueba: (1) los timers `apt-daily*` enmascarados e inactivos, (2) `99-soc-no-auto.conf` con sus 3 líneas y `apt-config dump` sin actualización automática, (3) `sshd -T` con `permitrootlogin no`, `passwordauthentication no`, `kbdinteractiveauthentication no`, `maxauthtries 3` y el puerto correcto (22222 en honeyserver), (4) que el demonio **en ejecución** solo ofrezca `publickey` (prueba que el `reload` llegó), (5) zona horaria `UTC`.

Para que no pasen en vacío, el entorno de ensayo parte sin endurecimiento: `sshd_config.tpl` solo incluye `sshd_config.d` y los contenedores nacen en `America/Mexico_City`.

Qué NO valida: la sincronía NTP real (`NTPSynchronized`, se exige en el tag `start` solo en host real), que `apt-daily*` exista y se pueda enmascarar en la imagen de Azure, y que la unidad de sshd se llame `ssh` en la imagen real.
EOF
tail -n 3 local/README.md | head -c 200
```

- [ ] **Step 3: Parchar la spec con los refinamientos**

Ejecutar:

```bash
cd ~/Projects/SOC-TESIS
python3 - <<'EOF'
import pathlib
p = pathlib.Path("docs/superpowers/specs/2026-10-29-common-role-design.md")
s = p.read_text()

def rep(old, new):
    global s
    assert s.count(old) == 1, (old, s.count(old))
    s = s.replace(old, new)

# Zona horaria sin dbus.
rep("Zona horaria `UTC` (`community.general.timezone`)",
    "Zona horaria `UTC` por enlace de `/etc/localtime` y `/etc/timezone` (`file` + `copy`; equivale a `timedatectl set-timezone` sin depender de dbus, igual en contenedor y host real)")

# Dockerfile del ensayo.
rep("y la imagen se reconstruye con `make clean preflight`.",
    "y la imagen se reconstruye con `make clean preflight`.\n- `ansible/local/Dockerfile`: instala `tzdata` y arranca los contenedores en `America/Mexico_City`, para que el check de zona horaria no pase en vacío (el contenedor ya nace en UTC).")

# Check 2 con el archivo del rol.
rep('2. `apt-config dump` muestra `Unattended-Upgrade "0"` y `Update-Package-Lists "0"`.',
    '2. Existe `/etc/apt/apt.conf.d/99-soc-no-auto.conf` con las tres líneas y `apt-config dump` muestra `Unattended-Upgrade "0"` y `Update-Package-Lists "0"` (la imagen de contenedor ya desactiva el periodo, así que solo el archivo prueba que actuó el rol).')

p.write_text(s)
print("spec parchada")
EOF
git diff --stat
```
Expected: `spec parchada` y diff en la spec, el README y `PIPELINE.md`.

- [ ] **Step 4: Escaneo de secretos y commit**

```bash
cd ~/Projects/SOC-TESIS/ansible && nix-shell --run 'make secret-scan'
cd .. && git add ansible/PIPELINE.md ansible/local/README.md docs/superpowers/specs/2026-10-29-common-role-design.md
git commit -m "docs(ansible): common-check, fila de hora en la Etapa 8 y refinamientos de la spec" -m "Zona horaria por enlace (sin dbus), fixture de zona en el Dockerfile y check 2 con el archivo del rol."
```
Expected: `secret-scan: ok (...)` y el commit creado.

---

## Self-Review

**Cobertura de la spec:**
- §1 Objetivo y "sin paquetes nuevos" → Tarea 2 (solo `copy`/`file`/`systemd_service`/`command`). ✔
- §2 Sin actualizaciones automáticas, antes del `apt`, `lock_timeout: 120` → Tarea 2, paso 3. ✔
- §2 Hora UTC (config) y NTP estricto en `start` solo en host real → Tarea 2, paso 3. ✔
- §2 sshd: drop-in, `validate`, handler `reload`, `assert` de `sshd -T`, variables `common_*` → Tarea 2, pasos 1-3. ✔
- §3 Errores: lockout (validate + reload + assert), candado dpkg (orden + lock_timeout), `apt-daily*` ausente (falla en voz alta), NTP sin egreso (fila en PIPELINE Etapa 8, Tarea 3 paso 1), reload sin cortar sesión. ✔
- §4 Pruebas: cambios al `sshd_config.tpl` y Dockerfile (Tarea 1), `common-check` con 5 checks (Tarea 1), `preflight` (Tarea 2). ✔
- §5 Criterio de listo → Tarea 2 paso 6 (`make clean preflight`, `rc=0`). ✔
- §6 Fuera de alcance: no se toca chrony, `policy-rc.d`, `strongswan`, Terraform. ✔

**Escaneo de placeholders:** sin TBD/TODO; todos los pasos de código muestran el código completo.

**Consistencia de nombres:** `common_timezone`/`common_ssh_max_auth_tries`/`common_ntp_retries`/`common_ntp_delay` (defaults) ↔ uso en tareas; `/etc/apt/apt.conf.d/99-soc-no-auto.conf` ↔ `common-check.sh`; handler `Recargar sshd` ↔ `notify`; `common_sshd_effective` registrado y usado en el `assert`; el drop-in `20-soc-hardening.conf` ↔ spec y constraints.

**Riesgos conocidos no verificables localmente:** NTP real, existencia y enmascarado de `apt-daily*` en la imagen de Azure y el nombre de la unidad `ssh` en la imagen real; se verifican en el primer ciclo (Etapas 6 y 8).
