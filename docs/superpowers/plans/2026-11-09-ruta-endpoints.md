# Ruta a "SOC en Azure monitoreando Windows 11 y Ubuntu" — Fase 4

> **Para agentes:** SUB-SKILL REQUERIDA: superpowers:executing-plans. Los pasos en la Pi, en los clientes y en Azure los ejecuta o autoriza el operador. Commits sin línea de coautor. Casillas `- [ ]`.

**Objetivo:** que los clientes Windows 11 (`192.168.1.75`) y Ubuntu (`192.168.1.74`) de la LAN (`192.168.1.0/24`) reporten a Wazuh (`10.50.40.10`) por el túnel, con eventos benignos visibles en el Dashboard y el ciclo `deallocate`/`start` recuperándose solo. Host de administración: `192.168.1.73` (IPs fijas por reserva MAC en el router, operador 2026-11-09).

## Estado al 2026-11-09 (tras el Día 4)

| Fase (plan maestro) | Estado |
|---|---|
| 1 Terraform y red | HECHO. 4 VMs, NSG con `for_each` (`4c67193`, plan no-op; `moved.tf` se borra tras el próximo `apply`) |
| 2 strongSwan + Pi | HECHO. SA sola en ~26 s con `close_action = start`; R1 solo en `.73` y sin persistencia |
| 3 Wazuh 4.14.10 | HECHO. 13 reglas locales + 100111 (sin commit) |
| **4 Endpoints Win11/Ubuntu** | **PENDIENTE: lo cubre este plan** |
| 5 Honeypots | HECHO. 7/7 `healthy`, Etapa M validada |
| 6 Log Relay | HECHO. Agente `honeyserver` `Active` vía relay |
| 7 Evidencia (Blob) | PENDIENTE. `terraform/evidence` sin aplicar |
| 8–12 | PENDIENTES. Dependen de la 4 (TEST-005) y de la 7 |

La red ya lo permite, así que la Fase 4 **no requiere tocar Terraform ni los roles**:
- NSG `Allow-Lab-Agents-1514-1515` y `Allow-Lab-Dashboard-443` desde `lab_cidr` hacia `10.50.40.10`.
- UFW de wazuh: 1514/1515/443 desde `wazuh_admin_cidr` (`192.168.1.0/24`).
- La Pi no hace NAT: Azure ve el origen `192.168.1.x`.

Lo que falta está en los clientes y en la Pi.

---

## E0 · Cierre de lo pendiente (local, sin costo)

- [ ] Validar la regla 100111: `cd ansible && nix-shell --run 'make clean preflight && make wazuh-rehearse rules-check && make clean'` (`wazuh-rehearse` necesita el stack arrancado y el relay configurado por `rehearse`, que corre dentro de `preflight`) → `rules-check: ok`. Después, commit de los 8 archivos modificados (100111 + documentación del Día 4).
- [ ] `git push` (la rama va 2 commits por delante) y abrir el PR de `merge/ansible-local`.
- [ ] Costos con días completos (desde el 2026-11-10): repetir la consulta de `d4-8b-costos-api.json` y cerrar el paso 8 del Día 4 frente a ≈ USD 35/mes.

## E1 · Inventario de clientes (sin costo)

- [x] Anotar la IP de cada cliente: Win11 `ipconfig`, Ubuntu `ip -4 a`. **Actualización 2026-11-09 (operador):** Win11, Ubuntu y el host de administración ya tienen reservada su IP por MAC en el router. Esto corrige lo que dice ADR-005 D3 ("el router no permite reservas") para los clientes; registrado en ADR-005 §2 con las 3 IP: host de administración `192.168.1.73`, Ubuntu `192.168.1.74`, Windows 11 `192.168.1.75`. **Pendiente (se hace al ejecutar E2):** comprobar que la IP observada en cada cliente (`ip -4 a` en Ubuntu, `ipconfig` en Windows) coincide con la reservada.
- [x] En la Pi, `sudo nft list set inet filter vpn_clients` (verificado 2026-11-09: las tres IP `.73`, `.74`, `.75` están en el set; sin cambios en la Pi) y reglas `rt ipsec exists/missing` intactas. Si faltaran, agregarlas en `/etc/nftables.conf` y aplicar `sudo nft -f /etc/nftables.conf`. **Gate:** autorización del operador (cambio en la Pi).

## E2 · R1 persistente en cada cliente (sin costo)

- [ ] **Ubuntu (`192.168.1.74`)** (NetworkManager): `nmcli con mod "<conexión>" +ipv4.routes "10.50.0.0/16 192.168.1.10" && nmcli con up "<conexión>"`. Con Netplan: `routes: [{to: 10.50.0.0/16, via: 192.168.1.10}]` y `netplan apply`.
- [ ] **Windows 11 (`192.168.1.75`)** (PowerShell como admin): `route -p add 10.50.0.0 mask 255.255.0.0 192.168.1.10`.
- [ ] Rechazar redirects ICMP (ADR-005, pendiente en los clientes). Ubuntu (`192.168.1.74`): `net.ipv4.conf.all.accept_redirects=0` en `/etc/sysctl.d/99-soc.conf`. Windows (`192.168.1.75`): `Set-NetIPv4Protocol -IcmpRedirects Disabled`.
- [ ] Verificar: Ubuntu (`192.168.1.74`) `ip route get 10.50.40.10` → `via 192.168.1.10`. Windows (`192.168.1.75`) `Find-NetRoute -RemoteIPAddress 10.50.40.10` → NextHop `192.168.1.10`. La ruta por defecto sigue en `192.168.1.254`.
- [ ] Reiniciar cada cliente y repetir la verificación (para confirmar que la ruta persiste).

## E3 · Instalar el agente sin enrolar (sin costo; los clientes tienen Internet)

La versión del agente debe ser la del Manager: **4.14.10** (un agente más nuevo que el Manager no se acepta).

**Secreto:** la contraseña de enrolamiento se pone en el archivo `authd.pass` del agente. **No** se usa `WAZUH_REGISTRATION_PASSWORD=…` en la línea de comandos, porque terminaría en el historial o en `argv` (misma regla que A3/E1-5).

- [ ] **Ubuntu (`192.168.1.74`):** repositorio `packages.wazuh.com/4.x/apt` con su llave GPG; `sudo WAZUH_MANAGER=10.50.40.10 WAZUH_AGENT_NAME=ubuntu-lab apt-get install wazuh-agent=4.14.10-1`; `sudo apt-mark hold wazuh-agent`. Copiar `~/soc-tesis-secrets/wazuh/authd.pass` a `/var/ossec/etc/authd.pass` (`0640 root:wazuh`) por `scp` + `install`. No hacer `enable` ni `start` todavía.
- [ ] **Windows 11 (`192.168.1.75`):** descargar `wazuh-agent-4.14.10-1.msi` y comparar su SHA-256 con el publicado. Instalar con `msiexec /i wazuh-agent-4.14.10-1.msi /q WAZUH_MANAGER=10.50.40.10 WAZUH_AGENT_NAME=win11-lab`. Copiar `authd.pass` a `C:\Program Files (x86)\ossec-agent\authd.pass` con permisos solo para Administradores/SYSTEM. No arrancar todavía.
- [ ] Higiene: `grep` del contenido de `authd.pass` en `~/.bash_history` del cliente Ubuntu (`192.168.1.74`) → 0; revisar que no quede copia en Descargas en Windows (`192.168.1.75`).

## E4 · Día 5 en Azure: enrolamiento y eventos (~1.5 h, con los gates habituales)

- [ ] Restaurar R1 en `.73`; `make time-guard pin-check`; `az vm start` en orden; SA `ESTABLISHED` sola; `ansible all -m ping` → 4 `pong`.
- [ ] Alcance desde cada cliente. Ubuntu (`192.168.1.74`): `nc -zv 10.50.40.10 1514` y `1515`. Windows (`192.168.1.75`): `Test-NetConnection 10.50.40.10 -Port 1514` y `-Port 1515` → `TcpTestSucceeded: True`. Si falla: revisar el set `vpn_clients` de la Pi (E1) antes que el NSG.
- [ ] Arrancar los agentes. Ubuntu (`192.168.1.74`): `sudo systemctl enable --now wazuh-agent`. Windows (`192.168.1.75`): `Start-Service WazuhSvc` (deja el servicio en automático).
- [ ] En el Manager: `ansible wazuh -b -m command -a '/var/ossec/bin/agent_control -l'` → `honeyserver`, `ubuntu-lab` y `win11-lab` `Active`. Ver también `/var/ossec/logs/ossec.log` en cada agente (`Connected to the server`).
- [ ] Eventos benignos (Fase 4.4). Anotar la hora de la acción y la hora de la alerta:
  - Ubuntu (`192.168.1.74`): 3 × `ssh nouser@localhost` con contraseña errónea y un `sudo` con contraseña errónea.
  - Windows (`192.168.1.75`): 3 logons fallidos (`runas /user:nouser cmd`) → EventID 4625. También crear y borrar un usuario local de prueba → 4720/4726.
- [ ] Confirmar en el Dashboard (`https://10.50.40.10` desde un cliente) que las alertas aparecen con el nombre de agente correcto (Fase 4.5). Guardar la consulta y los `rule.id` observados.
- [ ] Ciclo con agentes: `deallocate` en orden inverso; generar 2–3 eventos en cada cliente con Azure apagado; `start` en orden. Los agentes deben reconectar solos y entregar los eventos que guardaron en el buffer (es la base de TEST-008: anotar tiempo de reconexión y eventos perdidos).
- [ ] Evidencia en `evidence/azure/<fecha>/` (`d5-*`), `SHA256SUMS`, higiene 0/0 (PSK y `authd.pass`); `deallocate` en orden inverso.

**Hecho cuando:** 3 agentes `Active`; eventos benignos de Win11 (`192.168.1.75`) y Ubuntu (`192.168.1.74`) visibles en el Dashboard con su latencia anotada; tras el ciclo, los agentes reconectan sin intervención; ningún secreto en los clientes fuera de `authd.pass`.

**Consecuencia aceptada:** con Azure apagado, los agentes reintentan la conexión y acumulan eventos en el buffer; el tráfico es mínimo.

---

## Después de la Fase 4 (orden sugerido)

1. **Fase 7:** `terraform/evidence` (Blob 15 GB Cool LRS, inmutabilidad) con su propio gate de `apply`.
2. **Fase 8:** recorrer la lista de validación funcional con los 3 agentes y el Blob.
3. **Fase 9:** TEST-001…008, con las decisiones ya tomadas: TEST-001 con `-sV` (Dionaea no ve un connect scan) y TEST-002 por 100110 + 100111. **Decisión pendiente para TEST-005:** reglas por defecto de Windows (4625/4720/PowerShell) o añadir Sysmon. Recomendado: las reglas por defecto primero; Sysmon solo si deja un FN.
4. **Fases 10–12:** medición, evaluación y destroy/rebuild conservando el Blob.
