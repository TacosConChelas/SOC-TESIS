# Día 2 — Wazuh, honeypot, cierre y arranque (2026-11-08)

## Pre-vuelo (16:04 CST)
- `make time-guard`: ok (16:04). `make pin-check`: ok (Wazuh 4.14.10; Docker 29.8.2 / containerd 2.3.6 / Compose 5.6.0).
- IP pública del lab `203.0.113.10` (dentro de `lab_source_cidrs`). Sin red Docker `soc-local-operate`. Las 4 VMs partían `deallocated`.

## Primera observación del ciclo `start`
- `az vm start` en orden strongswan → wazuh → logrelay → honeyserver: 16:05:11 a ~16:08 (169 s en total), sin errores.
- Manual del operador: ruta R1 con MTU (`ip route replace 10.50.0.0/16 via 192.168.1.10 mtu 1360`) y `activar.sh 172.202.13.163` en la Pi. `swanctl --list-sas` estaba vacío antes (el túnel se terminó el Día 1).
- SA `ESTABLISHED` + `INSTALLED` a la primera, sin reintentos. `ping` 10.50.20.10 ~57 ms, 0 % de pérdida. `ansible all -m ping`: 4 pong.

## Etapa 3 · Abrir egreso (autorización escrita del operador)
- Plan: 4 add, 0 change, 0 destroy (4 × `Allow-Out-Maintenance-Egress`, prio 300, TCP 80/443 → Internet); 67 recursos sin cambio. Apply sin errores; `plan` posterior exit 0.
- `curl https://example.com` → 200 en las 4 VMs; túnel vivo.

## Etapa 6
| Etapa | Resultado | Log |
|---|---|---|
| 6b Wazuh | ok=70 changed=34 failed=0 (sin gate de versión) | `6b-pass1.log` |
| 6c Honeypot | ok=59 changed=32 failed=0 | `6c-pass1.log` |
| E1-3 tras 6c | `docker.service`, `docker.socket`, `containerd.service`, `wazuh-agent.service` = `inactive disabled`; `centinelas-ok` | `6c-pass1.log` |
| 6d idempotencia | `changed=0 failed=0 unreachable=0` en las 4 | `6d-pass2.log` |

6b y 6c se ejecutaron en paralelo (hosts distintos); el plan los pone en serie.

## Etapa 7 · Cierre de egreso (autorización escrita del operador)
- Sin descargas en curso (`pgrep` vacío en las 4). Plan: 0 add, 0 change, 4 destroy (solo las 4 reglas). Apply: 4 destroyed; `plan` posterior exit 0; sin archivos `/tmp/tfplan*`.
- `curl http://1.1.1.1` y `https://example.com`: fallan en las 4 (rc=28, timeout). `getent hosts example.com` resuelve en las 4. `ansible all -m ping`: 4 pong.

## Etapa 8 · Arranque
| Pasada | Resultado | Log |
|---|---|---|
| 1ª `--tags start` | honeyserver ok=13 changed=4; logrelay, strongswan, wazuh changed=0; failed=0 en las 4 (la aserción de egreso cerrado pasó) | `8-start1.log` |
| 2ª `--tags start` | `changed=0 failed=0` en las 4 | `8-start2.log` |

Verificaciones:
- SA `ESTABLISHED`/`INSTALLED` con tráfico (14 260 paquetes in / 4 305 out al medirlo).
- `wazuh-control info`: `WAZUH_VERSION="v4.14.10"`. indexer, manager, filebeat y dashboard `active enabled`.
- Puertos Wazuh: 1514, 1515 y 443 en 0.0.0.0; 55000 y 9200 solo en loopback.
- `agent_control -l`: `vm-honeyserver` `Active`; `wazuh-agentd.state` = `connected`.
- Relay: `nc -zv 10.50.30.10 1514/1515` conectan; `stream.log` con `10.50.10.10 … TCP 200`.
- Honeypot: 7 contenedores `healthy`; banner del 22 público `SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3` (Cowrie, no el del host); 22222 en escucha; `curl` al exterior falla.
- NTP `yes` en las 4 VMs con el egreso cerrado (PTP de Hyper-V basta).

## Evento de prueba (operador, desde fuera de Azure)
- `ssh -p 22 root@130.131.218.113` → Cowrie registra la sesión y el agente la envía al manager.
- Con `logall_json=yes` activado un momento en el manager (reiniciado con `wazuh-manager`; configuración restaurada y archivos de `archives` borrados después), llegaron 15 eventos de `vm-honeyserver`: `session.connect` 23:37:43.714Z → `login.success` 23:37:51.715Z → `session.params`. Extracto en `8-evento-prueba-archives.jsonl`.
- Un escáner externo ya golpeaba el honeypot minutos después del arranque.

## Hallazgo
- **No hay alerta para el evento:** `local_rules.xml` solo tiene la regla placeholder nivel 0 (`100000`). Las reglas de Cowrie (100100–100199) no existen aún, y `logall` queda en `no`. El pipeline agente → relay → manager funciona; falta la fase de reglas (`wazuh-logtest`).
- El plan da por hecho que el evento "aparece en Wazuh"; con `logall=no` solo se vería como alerta, que requiere reglas.

## Cierre
- `az vm deallocate` en orden inverso: honeyserver (17:40:02) → logrelay → wazuh → strongswan (fin 17:42:15). Las 4 VMs `VM deallocated`.
- Higiene: coincidencias de `psk.hex` y `authd.pass` en esta carpeta = 0.

## Pendiente para el Día 3
- Terminar el túnel en la Pi: `ssh -t soc71 sudo swanctl --terminate --ike lab` (operador).
- Tras reiniciar el equipo del operador, repetir la ruta R1 con MTU 1360.
- Ciclo `start` en orden, **sin tocar nada**: registrar si la SA se levanta sola (hoy hizo falta `activar.sh`), `ping`, los 7 contenedores `healthy`, agente `connected`, NTP, egreso cerrado. Pasada completa sin tags con `changed=0`, `--check --diff`, `terraform plan` exit 0, Cost Management vs ≈ USD 35/mes, y `deallocate`.
- Decidir cuándo se escriben las reglas de Cowrie y los demás honeypots.
