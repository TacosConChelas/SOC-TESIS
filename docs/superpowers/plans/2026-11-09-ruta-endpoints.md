# Ruta a "SOC en Azure monitoreando Windows 11 y Ubuntu" — Fase 4

> **Para agentes:** SUB-SKILL REQUERIDA: superpowers:executing-plans. Los pasos en la Pi, en los clientes y en Azure los ejecuta o autoriza el operador. Commits sin línea de coautor. Casillas `- [ ]`.

**Objetivo:** que los clientes Windows 11 (`192.168.1.75`) y Ubuntu (`192.168.1.74`) de la LAN (`192.168.1.0/24`) reporten a Wazuh (`10.50.40.10`) por el túnel, con eventos benignos visibles en el Dashboard y el ciclo `deallocate`/`start` recuperándose solo. Host de administración: `192.168.1.73` (IPs fijas por reserva MAC en el router, operador 2026-11-09).

## Estado

Fases 1, 2, 3, 5 y 6 hechas (ver plan maestro). Esta es la Fase 4; la red ya lo permite (NSG y UFW sin cambios, la Pi no hace NAT), así que **no requiere tocar Terraform ni los roles**. Lo que falta está en los clientes y en la Pi.

---

## E0 · Cierre de lo pendiente (local, sin costo)

- [x] Regla 100111 validada (`make clean preflight && make wazuh-rehearse rules-check` → `rules-check: ok (38 eventos)`) y commit `d1c9dfa`.
- [x] Push y merge `--no-ff` a `main` (`128b687`); sin PR (un solo autor). Rama `merge/ansible-local` borrada.
- [x] Costos con días completos (2026-11-13): fijo 0,72 USD/día, proyección ≈ 33,6 USD/mes frente a ≈ 35 (`evidence/azure/2026-11-09/d4-8c-costos-dias-completos.json`).

## E1 · Inventario de clientes (sin costo)

- [x] IP de cada cliente por reserva MAC en el router (operador 2026-11-09): `.73` administración, `.74` Ubuntu, `.75` Windows 11 (ADR-005 §2, corrige D3). La IP observada en cada cliente coincide con la reservada (verificado en E2).
- [x] En la Pi, `sudo nft list set inet filter vpn_clients` (verificado 2026-11-09: las tres IP `.73`, `.74`, `.75` están en el set; sin cambios en la Pi) y reglas `rt ipsec exists/missing` intactas. Si faltaran, agregarlas en `/etc/nftables.conf` y aplicar `sudo nft -f /etc/nftables.conf`. **Gate:** autorización del operador (cambio en la Pi).

## E2 · R1 persistente en cada cliente (sin costo)

**Estado:** R1 aplicado en Ubuntu y Windows; reinicio y verificación post-reinicio hechos el 2026-11-09/10, con evidencia en `e2-ubuntu-after-reboot.log` y `e2-windows-after-reboot.log`. El host de administración (.73) sigue sin persistencia por diseño. Incidencia: SSH a Windows (.75) tardó ~5 min en responder tras el reinicio (00:09:53 a 00:15), sin causa identificada; si se repite en E4, revisar que `sshd` arranque en automático.

- [x] **Ubuntu (`192.168.1.74`)**: `10.50.0.0/16 via 192.168.1.10` persiste por el YAML de Netplan (`/etc/netplan/00-installer-config.yaml`). El perfil de NetworkManager vive en `/run` y se regenera en cada arranque. Ruta por defecto `192.168.1.254` intacta.
- [x] **Windows 11 (`192.168.1.75`)**: ruta persistente (`route print -4` → "Persistent Routes", métrica 1) hacia `192.168.1.10`. Ruta por defecto `192.168.1.254` intacta.
- [x] Rechazar redirects ICMP (ADR-005, pendiente en los clientes). Ubuntu (`192.168.1.74`): `net.ipv4.conf.all.accept_redirects=0` (y `default`, `enp1s0`) en `/etc/sysctl.d/99-soc.conf`. Windows (`192.168.1.75`): `IcmpRedirects` = Disabled.
- [x] Verificar (pre-reinicio): Ubuntu `ip route get 10.50.40.10` → `via 192.168.1.10`. Windows `Find-NetRoute -RemoteIPAddress 10.50.40.10` → NextHop `192.168.1.10`. IP observada coincide con la reservada (.74 y .75).
- [x] Reiniciar cada cliente y repetir la verificación (para confirmar que la ruta persiste). Ambos clientes reiniciados; R1 persistente, ruta por defecto en `192.168.1.254` y redirects ICMP rechazados confirmados tras el reinicio.

## E3 · Instalar el agente sin enrolar (sin costo; los clientes tienen Internet)

La versión del agente debe ser la del Manager: **4.14.10** (un agente más nuevo que el Manager no se acepta).

**Secreto:** la contraseña de enrolamiento se pone en el archivo `authd.pass` del agente. **No** se usa `WAZUH_REGISTRATION_PASSWORD=…` en la línea de comandos, porque terminaría en el historial o en `argv` (misma regla que A3/E1-5).

- [x] **Ubuntu (`192.168.1.74`):** repositorio `packages.wazuh.com/4.x/apt` con su llave GPG; `sudo WAZUH_MANAGER=10.50.40.10 WAZUH_AGENT_NAME=ubuntu-lab apt-get install wazuh-agent=4.14.10-1`; `sudo apt-mark hold wazuh-agent`. Copiar `~/soc-tesis-secrets/wazuh/authd.pass` a `/var/ossec/etc/authd.pass` (`0640 root:wazuh`) por `scp` + `install`. No hacer `enable` ni `start` todavía.
  - *Hecho 2026-11-10:* wazuh-agent 4.14.10-1 instalado y en hold; sin enrolar; servicio `inactive` y `disabled`; `authd.pass` `-rw-r----- root:wazuh` (45 bytes). Evidencia: `evidence/azure/2026-11-10/e3-ubuntu.log`.
- [x] **Windows 11 (`192.168.1.75`):** descargar `wazuh-agent-4.14.10-1.msi` y comparar su SHA-512 con el publicado (Wazuh solo publica SHA-512: `packages.wazuh.com/4.x/checksums/wazuh/4.14.10/wazuh-agent-4.14.10-1.msi.sha512`). Instalar con `msiexec /i wazuh-agent-4.14.10-1.msi /q WAZUH_MANAGER=10.50.40.10 WAZUH_AGENT_NAME=win11-lab`. Copiar `authd.pass` a `C:\Program Files (x86)\ossec-agent\authd.pass` con permisos solo para Administradores/SYSTEM. No arrancar todavía.
  - *Hecho 2026-11-10:* wazuh-agent 4.14.10 instalado (msiexec exit 0); SHA-512 del MSI verificado contra el publicado; sin enrolar; `WazuhSvc` `Stopped` con StartType `Automatic` (sin cambiar); `authd.pass` con ACL solo `SYSTEM:(F)` y `Administrators:(F)`. Evidencia: `evidence/azure/2026-11-10/e3-windows.log`.
- [x] Higiene: `grep` del contenido de `authd.pass` en `~/.bash_history` del cliente Ubuntu (`192.168.1.74`) → 0; revisar que no quede copia en Descargas en Windows (`192.168.1.75`).
  - *Resultado 2026-11-10:* 0/0 (Ubuntu: 0 coincidencias en `.bash_history`, sin copia en `/tmp`; Windows: 0 `authd.pass*` en `C:\Users`, MSI y temporales eliminados).

## E4 · Día 5 en Azure: enrolamiento y eventos (~1.5 h, con los gates habituales)

- [x] Restaurar R1 en `.73` **con MTU**: `sudo ip route replace 10.50.0.0/16 via 192.168.1.10 mtu 1360` (sin `mtu`, el SSH a las VMs se cuelga en el KEX; ADR-006 E1-11; incidencia del 2026-11-13); `make time-guard pin-check`; `az vm start` en orden; SA `ESTABLISHED` sola; `ansible all -m ping` → 4 `pong`.
- [x] Alcance desde cada cliente. Ubuntu (`192.168.1.74`): `nc -zv 10.50.40.10 1514` y `1515`. Windows (`192.168.1.75`): `Test-NetConnection 10.50.40.10 -Port 1514` y `-Port 1515` → `TcpTestSucceeded: True`. Si falla: revisar el set `vpn_clients` de la Pi (E1) antes que el NSG.
- [x] Arrancar los agentes. Ubuntu (`192.168.1.74`): `sudo systemctl enable --now wazuh-agent`. Windows (`192.168.1.75`): `Start-Service WazuhSvc` (deja el servicio en automático).
- [x] En el Manager: `ansible wazuh -b -m command -a '/var/ossec/bin/agent_control -l'` → `honeyserver`, `ubuntu-lab` y `win11-lab` `Active`. Ver también `/var/ossec/logs/ossec.log` en cada agente (`Connected to the server`).
- [x] Eventos benignos (Fase 4.4). Anotar la hora de la acción y la hora de la alerta:
  - Ubuntu (`192.168.1.74`): 3 × `ssh nouser@localhost` con contraseña errónea y un `sudo` con contraseña errónea.
  - Windows (`192.168.1.75`): 3 logons fallidos (`runas /user:nouser cmd`) → EventID 4625. También crear y borrar un usuario local de prueba → 4720/4726.
- [x] Confirmar en el Dashboard (`https://10.50.40.10` desde un cliente) que las alertas aparecen con el nombre de agente correcto (Fase 4.5). Guardar la consulta y los `rule.id` observados.
- [x] Ciclo con agentes: `deallocate` en orden inverso; generar 2–3 eventos en cada cliente con Azure apagado; `start` en orden. Los agentes deben reconectar solos y entregar los eventos que guardaron en el buffer (es la base de TEST-008: anotar tiempo de reconexión y eventos perdidos).
- [x] Evidencia en `evidence/azure/<fecha>/` (`d5-*`), `SHA256SUMS`, higiene 0/0 (PSK y `authd.pass`); `deallocate` en orden inverso.
  - *Hecho 2026-11-13:* 3 agentes `Active`; latencia de alerta Ubuntu 0,14–0,35 s y Windows ~0,9 s; ciclo con agentes: caída de 13 min 28 s, SA sola en ~33 s, 0 eventos perdidos y 0 duplicados (base de TEST-008). **Causa que bloqueaba el alcance y el enrolamiento:** faltaba un MSS-clamp en el túnel (segmentos de 1410 B del Manager sin ACK); se resolvió con dos reglas `maxseg size set 1320` en la cadena `forward` de la Pi, persistidas en `/etc/nftables.conf`. Desvíos: `runas` → `net use` (sin TTY por SSH), `sudo` con contraseña errónea → 4.º login SSH (la cuenta es `NOPASSWD`), reloj de Win11 corregido (+7200 s). Evidencia: `evidence/azure/2026-11-13/` (`d5-*`, `11-cierre-dia5.md`).

**Hecho cuando:** 3 agentes `Active`; eventos benignos de Win11 (`192.168.1.75`) y Ubuntu (`192.168.1.74`) visibles en el Dashboard con su latencia anotada; tras el ciclo, los agentes reconectan sin intervención; ningún secreto en los clientes fuera de `authd.pass`.

---

**Decisión pendiente para TEST-005 (Fase 9):** reglas por defecto de Windows (4625/4720/PowerShell) o añadir Sysmon. Recomendado: las reglas por defecto primero; Sysmon solo si deja un FN.
