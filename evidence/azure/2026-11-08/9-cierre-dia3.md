# Día 3 — Ciclo deallocate/start y aceptación (2026-11-08, noche UTC 11-09)

## Pre-vuelo (17:58 CST)
- `make time-guard` ok; `make pin-check` ok (Wazuh 4.14.10). Las 4 VMs `deallocated`; ruta R1 (con MTU 1360) vigente; sin red Docker local. La Pi llevaba 20 h encendida con `strongswan` activo.

## Ciclo `start` sin tocar nada
- `az vm start` en orden strongswan → wazuh → logrelay → honeyserver: 17:59:11 a 18:02:04 (173 s), sin errores.
- **La SA no se levantó sola:** `ping 10.50.20.10` sin respuesta durante 300 s (hasta 18:08). `swanctl --list-sas` en la Pi: vacío. Hizo falta `activar.sh 172.202.13.163` a mano (P8: arranca sin `enable`).
- IPs públicas conservadas (ambas `Static`): strongswan 172.202.13.163, honeyserver 130.131.218.113.
- Tras `activar.sh`: ping ~58 ms, 0 % de pérdida; `ansible all -m ping`: 4 pong.

## Qué sobrevive / qué no
| Elemento | Resultado |
|---|---|
| IPs públicas | sobreviven |
| SA del túnel | **no** (intervención: `activar.sh`) |
| Wazuh (indexer, manager, filebeat, dashboard) | sobreviven, `active` |
| Agente `honeyserver` | sobrevive, `connected`/`Active` |
| NTP | sobrevive, `yes` en las 4 |
| Egreso | sigue cerrado (`curl` rc=28 en las 4) |
| Contenedores del honeypot | **5 de 7 `healthy`; `tanner` y `snare` fallan** (ver hallazgo) |

## Hallazgo: tanner no sobrevive al ciclo
- Síntoma: `tanner` en bucle (`Restarting (1)`, 26 reinicios desde el arranque del host a las 00:01Z) por `PermissionError: /tmp/tanner/tanner.err`; `snare` depende de él (`Can't connect to tanner host`).
- Causa, reproducida en un contenedor desechable con la misma imagen: con `tmpfs: /tmp/tanner` sin `mode`, el 1er arranque deja `1777`; del 2º en adelante queda `0755` root (hereda del punto de montaje) y el usuario `tanner` no escribe. El Día 2 funcionó porque era el primer arranque del contenedor recién creado.
- Con `mode=1777` explícito, 3 arranques seguidos escriben bien.
- Corrección (commit `0689283`): `docker-compose.yml` con `/tmp/tanner:mode=1777` y `/opt/tanner/files:mode=1777` (phpox ya tenía el modo explícito).
- Check nuevo `c10` en `honeypot-check.sh`: reinicia tanner dos veces y exige `healthy`. **Ensayo local pendiente** (la red Docker `10.50.0.0/16` solapa con la ruta R1; hacerlo tras quitar R1).
- Por qué el ensayo local no lo vio: ningún ensayo arrancaba dos veces un contenedor ya creado.

## Redespliegue de la corrección (sin egreso)
| Paso | Resultado | Log |
|---|---|---|
| `--check --diff` (install,config) | changed=1 (solo "Copiar docker-compose.yml y .env") | `9-fix-tanner-check.log` |
| install,config | ok=47 changed=1 failed=0 | `9-fix-tanner-config.log` |
| start (recrea tanner) | ok=13 changed=1 failed=0 | `9-fix-tanner-start1.log` |
| 2ª start | changed=0 failed=0 | `9-fix-tanner-start2.log` |
| 3 reinicios de tanner (filtro exacto) | `healthy` a los 10 s en los 3, modo 1777; snare healthy; 7 de 7 healthy; RestartCount 0 | `9-fix-tanner-c10.log` |

La primera prueba de reinicio del agente midió mal (el filtro `soc-tesis-tanner` también coincidía con `-redis` y `-phpox`); se repitió con filtro exacto.
**No verificado todavía:** el arreglo se probó con `docker restart`, no con un `deallocate`/`start` real. Se confirma en el próximo arranque de las VMs.

## Aceptación (Etapa 9)
| Comprobación | Resultado | Log |
|---|---|---|
| Pasada completa sin tags | `changed=0 failed=0 unreachable=0` en las 4 | `9-full.log` |
| `--check --diff` | `changed=0 failed=0` en las 4 | `9-check-diff.log` |
| `terraform plan -var maintenance_egress=false -detailed-exitcode` | exit 0, "No changes" | (consola) |
| Cost Management | **no disponible**: `az consumption` devuelve 6 filas sin importe (Azure tarda 8–24 h) y la extensión `costmanagement` no está instalada. Repetir en 24 h y comparar con ≈ USD 35/mes (ADR-006 §6) | — |

## Cierre
- `az vm deallocate` en orden inverso: honeyserver (18:33:46) → logrelay → wazuh → strongswan (fin 18:35:56). Las 4 VMs `VM deallocated`.

## Pendiente
- Operador: terminar el túnel en la Pi (`ssh -t soc71 sudo swanctl --terminate --ike lab`) y quitar la ruta R1 antes del ensayo local (`sudo ip route del 10.50.0.0/16`).
- Ensayo local con `c10`: `make clean preflight wazuh-rehearse honeypot-rehearse`; después `make clean`.
- Confirmar tanner tras un `deallocate`/`start` real en el próximo arranque.
- Repetir la consulta de costos pasadas 24 h.
- Decidir si el túnel debe autorrecuperarse (hoy requiere `activar.sh` tras cada `start`).
- Reglas de Cowrie y demás honeypots (100100–100499), aún sin escribir.
