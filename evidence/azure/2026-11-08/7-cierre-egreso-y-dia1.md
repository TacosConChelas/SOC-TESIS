# Etapa 7 (ensayo temprano) y cierre del Día 1 — 2026-11-08

## Cierre de egreso (gate: autorización escrita del operador)
- Plan `maintenance_egress=false`: 4 × `delete` de `Allow-Out-Maintenance-Egress` (prio 300, Allow, Internet) en honeypot, logrelay, vpn y wazuh. Sin otros cambios.
- `terraform apply`: 0 added, 0 changed, 4 destroyed. Plan borrado de /tmp.

## Verificaciones (4 VMs)
| Prueba | Esperado | Resultado |
|---|---|---|
| `curl -m5 http://1.1.1.1` | falla | falla en las 4 (rc=28, timeout) |
| `curl -m5 https://example.com` | falla | falla en las 4 (rc=28, timeout) |
| `getent hosts example.com` | resuelve | resuelve en las 4 |
| `ansible all -m ping` | 4 pong | 4 pong (el túnel sigue vivo) |

## Cierre del día
- `az vm deallocate` en orden inverso: honeyserver → logrelay → wazuh → strongswan.
- Estado final: las 4 VMs `VM deallocated`.

## Pendiente para el Día 2
- Terminar el túnel en la Pi: `ssh -t soc71 sudo swanctl --terminate --ike lab` (lo ejecuta el operador).
- Tras reiniciar el equipo del operador, repetir la ruta R1 **con MTU**: `sudo ip route replace 10.50.0.0/16 via 192.168.1.10 mtu 1360` (sin ella el SSH se cuelga; ver ADR-006 E1-11).
- Arranque en orden: strongswan → wazuh → logrelay → honeyserver; en la Pi `swanctl --list-sas` y, si no hay SA, `--initiate`.
- El Día 2 vuelve a abrir el egreso (Etapa 3, con gate) para Wazuh (>1 GB) y el honeypot.
