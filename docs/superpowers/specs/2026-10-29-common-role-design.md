# Diseño del rol Ansible `common`

**Fecha:** 2026-10-29
**Rama:** `practica/ansible-local`
**Estado:** diseño aprobado por el operador; pendiente de plan de implementación.
**Fuentes:** ADR-006 (E1-3, E1-7, E1-8), `.knowledge/17_SOFTWARE_BASELINE.md` (D1), `ansible/PIPELINE.md`, revisión final del rol `logrelay` (riesgo de `unattended-upgrades`).
**Contexto:** segundo subproyecto de P-A1. `common` corre en las 4 VMs antes que cualquier otro rol.

## 1. Objetivo

Ampliar el rol `common`, que hoy instala `ca-certificates` y `curl`, escribe el `policy-rc.d` (E1-3) y deja un marcador, con tres bloques acordados con el operador: sin actualizaciones automáticas, hora en UTC verificada y sshd endurecido. No se agrega ningún paquete nuevo.

## 2. Contenido y tags

| Bloque | Tag | Qué hace | Descarga |
|---|---|---|---|
| Sin actualizaciones automáticas | `config` | Escribe `/etc/apt/apt.conf.d/99-soc-no-auto.conf` con `APT::Periodic::Update-Package-Lists`, `APT::Periodic::Unattended-Upgrade` y `APT::Periodic::Download-Upgradeable-Packages` en `"0"`; detiene, deshabilita y enmascara `apt-daily.timer` y `apt-daily-upgrade.timer`. Va **al principio** del archivo de tareas, antes del `apt`, para que una actualización de arranque no retenga el candado de dpkg | No |
| Hora UTC | `config` | Zona horaria `UTC` por enlace de `/etc/localtime` y `/etc/timezone` (`file` + `copy`; equivale a `timedatectl set-timezone` sin depender de dbus, igual en contenedor y host real) | No |
| Hora sincronizada | `start` | Solo en host real (`when: ansible_virtualization_type != 'docker'`): `timedatectl show -p NTPSynchronized --value` debe valer `yes`, con 12 reintentos de 10 s; si no, el play **falla** (decisión del operador: estricto). Solo lectura (`changed_when: false`) | No |
| sshd endurecido | `config` | Drop-in `/etc/ssh/sshd_config.d/20-soc-hardening.conf` con `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no` y `MaxAuthTries 3`; `validate: /usr/sbin/sshd -t -f %s`; aplicado con un handler `reload` (nunca `restart`); después, una tarea `sshd -T` con `assert` de los valores efectivos | No |

La tarea `apt` de `common` agrega `lock_timeout: 120`.

Detalles:
- El drop-in no define `Port`, por lo que no choca con el `10-admin-port.conf` de honeyserver (E1-2). Se llama `20-` para que, con "primer valor gana", no lo pise nada posterior; los archivos anteriores (`10-*`) se detectan por el `assert` de valores efectivos.
- El `policy-rc.d` y el marcador no cambian.
- Variables con prefijo `common_` (regla `var-naming[no-role-prefix]` de `ansible-lint`), en `defaults/main.yml`: `common_ssh_max_auth_tries` (3), `common_timezone` (`UTC`), `common_ntp_retries` (12), `common_ntp_delay` (10).

## 3. Errores y casos límite

| Riesgo | Comportamiento |
|---|---|
| Drop-in de sshd mal formado | `validate` lo rechaza antes de escribirlo; `reload`, no `restart`. El `assert` de `sshd -T` falla si los valores efectivos difieren (cubre también una pasada en VM real). Rescate: `az vm run-command` y revertir el archivo. |
| Actualización de arranque retiene el candado de dpkg | Los timers se enmascaran primero y el `apt` usa `lock_timeout: 120`. |
| `apt-daily*` no existe en la imagen | `systemd_service` falla en voz alta; en Ubuntu 22.04 de Azure existen; se confirma en el primer ciclo. |
| La hora no sincroniza sin egreso | El `start` falla tras unos 2 min. Entonces se decide si hace falta configurar el PTP de Hyper-V en chrony. Se agrega una fila a la Etapa 8 de `PIPELINE.md`. |
| Cambio de sshd durante una sesión de Ansible | `reload` no corta conexiones establecidas. |

## 4. Pruebas locales

Cambios al entorno de ensayo para que los checks no pasen en vacío:
- `ansible/local/sshd_config.tpl`: se agrega `Include /etc/ssh/sshd_config.d/*.conf` como primera línea (como Ubuntu) y se quitan `PermitRootLogin no`, `PasswordAuthentication no` y `KbdInteractiveAuthentication no`. Así esos valores solo pueden venir del rol. Es seguro porque las cuentas de los contenedores no tienen contraseña, y la imagen se reconstruye con `make clean preflight`.
- `ansible/local/Dockerfile`: instala `tzdata` y arranca los contenedores en `America/Mexico_City`, para que el check de zona horaria no pase en vacío (el contenedor ya nace en UTC).

Target nuevo `make common-check` (en `preflight`, después de `relay-check`), sobre las 4 VMs, con exit ≠ 0 si algo falla:

1. `apt-daily.timer` y `apt-daily-upgrade.timer` figuran como `masked` y no están activos.
2. Existe `/etc/apt/apt.conf.d/99-soc-no-auto.conf` con las tres líneas y `apt-config dump` muestra `Unattended-Upgrade "0"` y `Update-Package-Lists "0"` (la imagen de contenedor ya desactiva el periodo, así que solo el archivo prueba que actuó el rol).
3. `sshd -T` muestra `permitrootlogin no`, `passwordauthentication no`, `kbdinteractiveauthentication no` y `maxauthtries 3`; puerto 22222 en honeyserver y 22 en el resto.
4. Un intento de login por contraseña desde el host recibe `Permission denied (publickey)` y no `(publickey,password)` (el `reload` llegó al demonio en ejecución).
5. `timedatectl` reporta `UTC`.

La doble pasada con `changed=0` de la Etapa 0 cubre la idempotencia, incluido que el handler solo corra cuando hay cambio.

**No se valida en local:** la sincronía NTP real, que `apt-daily*` exista y se pueda enmascarar en la imagen de Azure, y que el servicio de sshd se llame `ssh` en la imagen real (se asume por Ubuntu 22.04).

## 5. Criterio de listo

- `make common-check` pasa (los 5 checks).
- `make clean preflight` termina con rc=0, con 2ª pasada en `changed=0`, y `relay-check` sigue en verde.
- Lint, contrato de tags y escaneo de secretos limpios.
- Los cambios se limitan a `ansible/` y `docs/`; no se toca `terraform/` ni `.knowledge/`.

## 6. Fuera de alcance

- Fijar versiones de `ca-certificates` y `curl`.
- Configurar chrony o el PTP de Hyper-V.
- Retirar el `policy-rc.d`.
- `fail2ban`, `auditd`.
- El rol `strongswan`.
