# Fase 8 — Cierre · acta (2026-11-14, 02:08–cierre CST)

Continúa `../2026-11-13-f8/13-acta-fase8.md` (inmutable en Blob; no se edita). Logs `f8b-*` de esta carpeta. IP del operador en el hotspot → `203.0.113.10` / `203.0.113.11`; IPs de terceros → `198.51.100.x`; GUIDs → `<guid>`.

**Veredicto propuesto: ACEPTADA CON RESERVAS.** Los 5 pendientes del acta del 13-nov están atendidos. Reservas: (a) B4 sin observación directa del operador en Discover (ver punto 2); (b) hallazgo nuevo de pérdida Filebeat → Indexer, **abierto y sin corregir** (hallazgo 7).

## Pendientes del acta del 13-nov

| # | Pendiente | Resultado | Evidencia |
|---|---|---|---|
| 1 | Relojes `.74`/`.75`, filas 3f y 3g | ✅ Relojes corregidos (Ubuntu +0,4 ms, Windows +11 ms vs NTP). 3f → 5710, MTTD 1,06 s. 3g → 60122 (EventID 4625), MTTD 0,42 s | `f8b-3-estimulos.log`, `f8b-3-alertas.txt` |
| 2 | B4 Dashboard y notas del Día 5 | ⚠️ **Parcial.** El operador observó la vista general (3 agentes activos; High 1 / Medium 2,124 / Low 5,128; evento crítico 04:35:21 CST). Las consultas de Discover las ejecutó Claude contra el Indexer, **no** el operador; el hueco "Lo observado por el operador" de `2026-11-13/d5-7-dashboard.md` sigue sin observación directa | `f8b-4-dashboard.md` |
| 3 | 3c Mailoney desde un origen sin bloqueo del 25 | ✅ Hotspot móvil sin bloqueo. Sesión con pausas: 3 comandos, 100300 con el origen del operador, sin 100301 (~2 s log→alerta) | `f8b-3-alertas.txt` |
| 4 | ISM del índice 2026-11-08 | ✅ `_ism/add` aplicado; 4 de 4 índices con `wazuh-alert-retention-policy`; el 08-nov en `retention_state`, `enabled: true` | `f8b-5-ism.log` |
| 5 | `make rules-check` local con 100301 ampliada | ✅ `wazuh-analysisd -t` ok; `rules-check: ok (41 eventos)`. Se corrió con el manager del ensayo local, sin completar `wazuh-rehearse` (ver hallazgo 8) | sesión local (sin log en esta carpeta) |

## Hallazgos nuevos

1. **Relojes: ~17 h de atraso, no 8 h.** Causa: `ubuntu-soc` y `win11-soc` son VMs de libvirt en el host del operador; sin agente QEMU sus relojes se congelan cuando el host se suspende. Verificar el reloj de `.74`/`.75` justo antes de cada RUN de la Fase 9.
2. **Mailoney cuenta una ráfaga como 1 solo comando.** Con las 3 líneas de golpe: `command_count: 1`; con 1 s de pausa entre ellas: 3. Desde el hotspot la ráfaga no produjo ningún comando (solo `220`, 10,1 s). **TEST-004 debe enviar los comandos SMTP con pausas.**
3. **Origen externo de Mailoney validado** (cierra el hallazgo 3 del 13-nov): el 25 de salida pasa por el hotspot. El `src_ip` sigue solo en `full_log` (sin decoder JSON); decidir si TEST-004 lo necesita decodificado.
4. **Tráfico real detectado:** 100104 (nivel 12, "Cowrie: el atacante descargó un fichero al señuelo", `vm-honeyserver`) a las 2026-11-14 10:35:21Z desde `198.51.100.x` por telnet. Única alerta High de las últimas 24 h.
5. **Alertas de diagnóstico propias en el índice:** 20 alertas 100300 con origen `172.19.0.1` (10:38:55–10:39:27Z), generadas por una prueba de Claude desde el honeyserver (docker-proxy hace que 127.0.0.1 llegue como `172.19.0.1` y la 100301 no las filtra). **Excluirlas de cualquier conteo de 3c o TEST-004.**
6. **El diagnóstico del punto 5 se ejecutó dos veces:** la primera salida quedó oculta por un filtro del propio comando y se repitió. Ambas ejecuciones están dentro de las 20 alertas contadas.
7. **PÉRDIDA Filebeat → Indexer (abierto).** La 100410 `sqli` del 2026-11-13 20:33:28Z (3e1) está en `alerts.json` del Manager pero **no en el Indexer**: Filebeat la rechazó a las 20:33:31Z con `max_bytes_length_exceeded_exception` (`data.response_msg.response.message.detection.payload.value`, 34 682 > 32 766 bytes) y no la reintenta (error 400 de mapeo). Es el único `Cannot index event` en los 8 ficheros rotados. **Impacto:** Dashboard y consultas al Indexer no verán eventos con ese payload; el ground truth de TEST-001/TEST-006 debe medirse contra `alerts.json` o documentar un FN. Corrección posible (decisión del operador): truncar/ignorar el campo en el pipeline.
8. **El ensayo local `wazuh-rehearse` no termina:** tras converger Wazuh (1.ª pasada, 2.ª idempotente y `--check` sin cambios) falla en el paso del agente del arnés (`nginx del relay no esta activo`, requiere `make rehearse` previo). No afecta a la Fase 8; revisar antes del ensayo de la Fase 9.
9. **`sudo` bloqueado en la sesión de Claude** (`no new privileges`): la ruta R1 (`10.50.0.0/16 via 192.168.1.10 mtu 1360`) la puso el operador.

## Medidas de esta sesión

- Arranque 1: 4 VMs en orden, 43 s cada una (08:11:12Z → 08:14:05Z). Arranque 2 para 3c: 04:24 CST. Relojes Azure (chrony): offset < 6 µs en las 4 VMs.
- Agentes: `vm-honeyserver`, `win11-lab`, `ubuntu-lab` con alertas en los últimos 40 min; 7/7 honeypots `healthy`.
- Índices: 4 `green` (`2026.11.08/09/13/14`).

## Cierre

- Regresión `site.yml` sin tags: honeyserver ok=55 changed=0 failed=0; logrelay ok=30 changed=0 failed=0; strongswan ok=21 changed=0 failed=0; wazuh ok=52 changed=0 failed=0 (`f8b-7-regresion.log`).
- Subida a Blob: ver `../2026-11-14-f8b-sync.log` (se registra fuera de esta carpeta, porque lo subido es inmutable).
- Deallocate en orden inverso: ver `../2026-11-14-f8b-cierre.log`.

## Pendientes que quedan abiertos

- [ ] Observación directa del operador en Discover para el hueco del Día 5 (`2026-11-13/d5-7-dashboard.md`).
- [ ] Decidir y corregir la pérdida Filebeat → Indexer (hallazgo 7) o aceptar el FN documentado.
- [ ] Decidir si TEST-004 necesita `src_ip` de Mailoney decodificado (hallazgo 3).
- [ ] Corregir `make wazuh-rehearse` / relay antes de la Fase 9 (hallazgo 8).
