# Fase 8 — Validación funcional integrada · acta (2026-11-13, 14:06–cierre CST)

Plan: `docs/superpowers/plans/2026-11-14-fase8-validacion-funcional.md` (local). Logs `f8-*` de esta carpeta. IP pública del operador → `203.0.113.10`; IPs de terceros → `198.51.100.x`; GUIDs → `<guid>`. Carpeta aparte de `2026-11-13/` porque aquella ya está en Blob (inmutable).

**Veredicto: PARCIAL.** Fuentes de Azure (honeypots, recepción, procesamiento, historial, almacenamiento) aceptadas. Quedan pendientes 3f/3g (endpoints) y B4 (Dashboard), y el alcance externo de Mailoney (3c) no se pudo probar desde el laboratorio.

## Criterio de aceptación

| Punto (doc 06, Fase 8) | Resultado | Evidencia |
|---|---|---|
| Recepción | ✅ 3 agentes `Active` (`vm-honeyserver`, `win11-lab`, `ubuntu-lab`); Cowrie, Dionaea y Tanner con alerta desde Internet | `f8-0-arranque.log`, `f8-3-alertas.jsonl` |
| Procesamiento | ✅ cada fila ejecutada dio su `rule.id`; 0 alertas 100300 del healthcheck en 2 × 120 s tras 100301 | `f8-1-reglas.log`, `f8-2-base.log` |
| Alertas (MTTD ≤ 60 s) | ✅ 3a 2,1 s · 3b 1–2 s · 3d 0,8 s · 3e1 1,5 s · 3e2 2,0 s | `f8-3-estimulos.log`, `f8-3-alertas.jsonl` |
| Dashboard | ⏳ **PENDIENTE (B4)**: no observado por el operador en esta sesión | — |
| Historial | ✅ 3 índices `green`; 10 × 100102 del 2026-11-09 consultables. ⚠️ ISM en 2 de 3 índices (ver hallazgo 4) | `f8-5-historial.log` |
| Honeypots | ✅ 7/7 `healthy` tras el arranque; Mailoney ⚠️ (hallazgo 3) | `f8-0-arranque.log` |
| Almacenamiento | subida de esta carpeta con `evidence-sync.sh` al cierre | `f8-6-sync.log` |

## Filas de B3

| Fila | Esperado | Observado | MTTD |
|---|---|---|---|
| 3a Cowrie | 100101 | 100101 ×1, `data.src_ip` = operador | 2,1 s |
| 3b Dionaea (`nmap -sT`) | 100200 ×5 + 100210 | **nada** (ver hallazgo 2) | — |
| 3b-bis Dionaea (`nmap -sT -sV --version-light`) | 100200 ×5 + 100210 | 100200 ×6 (21, 445, 1433 ×2, 1883, 3306) + 100210 ×1 | 1–2 s |
| 3c Mailoney | 100300 | **nada**: no llega ningún paquete al honeyserver (hallazgo 3) | — |
| 3d Tanner | 100400 | 100400 ×1, `data.peer.ip` = operador | 0,8 s |
| 3e1 Tanner sqli | 100410 | 100410 `sqli` | 1,5 s |
| 3e2 Tanner xss | 100410 | 100410 `xss` | 2,0 s |
| 3f Ubuntu | 5710 | **PENDIENTE** (reloj, hallazgo 5) | — |
| 3g Windows | 60122 | **PENDIENTE** (reloj, hallazgo 5) | — |

## Medidas

- Arranque: 4 VMs en orden, 43–45 s cada una (14:06:51 → 14:09:54). SA `ESTABLISHED` sola durante el arranque de vm-strongswan (~20:08:05Z).
- Relojes Azure (chrony): offset < 2 µs en las 4 VMs.
- Recursos en reposo (`vmstat 10 30`, todo encendido): wazuh 99,0 % idle, 9,7/16 GB usados (6,0 GB disponibles), sin swap, disco `/` 37 % (23/62 GB); logrelay 99,9 % idle, 319 MB libres mín.; honeyserver 96,2 % idle, 1,9 GB libres mín. Línea base para TEST-007.
- Tráfico real de Internet durante la sesión: ~280 eventos Cowrie y 320 logins aceptados (100102) en el índice del día, SIP/UDP 5060 en Dionaea.

## Hallazgos

1. **Healthcheck de Mailoney = FP de nivel 5 cada 15 s.** Corregido con la regla 100301 (`fb9cf48`), ampliada en sesión con la variante `Connection closed for 127.0.0.1:` (`7bf8c47`, validada con `wazuh-logtest` en vm-wazuh). Pendiente: `make rules-check` local con el ensayo levantado.
2. **`nmap -sT` es invisible para Dionaea**: el connect scan cierra con RST tras el handshake y Dionaea no registra el `accept`. Con `-sV` (intercambio de datos) sí. **Impacto en TEST-001/TEST-006:** el ground truth debe usar escaneos con intercambio de datos o asumir FN documentados para el connect scan puro.
3. **El puerto 25 de salida está bloqueado en el ISP del laboratorio**: `nc` al 25 no produce ningún paquete en `tcpdump` del honeyserver (el 21 sí). La cadena Mailoney → journald → Wazuh está probada (100300 del healthcheck antes de 100301), el alcance externo no. Azure también bloquea el 25 saliente. **Bloquea TEST-004** hasta tener un origen sin filtro (p. ej. hotspot móvil). Además, el `src_ip` de Mailoney solo está en `full_log` (no hay decoder JSON); decidir si TEST-004 lo necesita decodificado.
4. **ISM no gestiona `wazuh-alerts-4.x-2026.11.08`**: el índice es anterior a la política y la plantilla solo aplica a índices nuevos. No se borrará a los 30 días. Corrección posible: `_plugins/_ism/add` sobre ese índice (decisión del operador; no se hizo).
5. **Relojes de los clientes ~8 h 17–20 min atrasados** (Ubuntu `.74` con `System clock synchronized: no`; Windows `.75`). Invalidan el MTTD de endpoints (doc 19: > 500 ms). Ambos con el mismo desfase: probable suspensión/reanudación. Revisar antes de cualquier RUN de la Fase 9.
6. **ICMP bloqueado por diseño** hacia wazuh/honeyserver (sin regla ICMP en los NSG). La verificación del túnel se hace por TCP (22/1514/443, 22222) y ping a 10.50.20.10.

## Pendientes para cerrar la Fase 8

- [ ] Corregir relojes de `.74` y `.75`; ejecutar 3f y 3g (sesión corta).
- [ ] B4: observación del operador en el Dashboard (incluye completar `../2026-11-13/d5-7-dashboard.md`).
- [ ] 3c desde un origen sin bloqueo del 25.
- [ ] Decisión sobre ISM del índice 2026-11-08.
- [ ] `make rules-check` local con la 100301 ampliada.

## Cierre

- Regresión `site.yml` sin tags: honeyserver ok=55 changed=0 failed=0; logrelay ok=30 changed=0 failed=0; strongswan ok=21 changed=0 failed=0; wazuh ok=52 changed=0 failed=0 (`f8-7-regresion.log`).
- Subida a Blob: ver `f8-6-sync.log` (se registra fuera de esta carpeta tras subir, porque lo subido es inmutable).
- Deallocate en orden inverso: ver `../2026-11-13-f8-cierre.log`.
