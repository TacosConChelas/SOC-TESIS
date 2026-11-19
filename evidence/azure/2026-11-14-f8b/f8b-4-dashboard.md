# F8b-4 · Dashboard (B4) y consultas equivalentes

Fecha: 2026-11-14 (CST). IP del operador en el hotspot → `203.0.113.10`; IPs de terceros → `198.51.100.x`. El Dashboard muestra la hora en **CST** (UTC−6).

## 1. Observación del operador en el Dashboard (literal)

Vista "Last 24 hours alerts":

- High severity: **1** (rule level 12 to 14)
- Medium severity: **2,124** (rule level 7 to 11)
- Low severity: **5,128** (rule level 0 to 6)
- "aparecen los 3 agentes activos: vmhoneyserver, win11 y ubuntu"
- "el evento critico aparece a las 'Nov 14, 2026 @ 04:35:21.008'"

Cruce con el Indexer (mismo rango, consultado más tarde): High 1 · Medium 2,245 · Low 5,215. La diferencia de Medium/Low es el tiempo transcurrido entre ambas lecturas. El evento crítico es **100104** (nivel 12, `vm-honeyserver`, "Cowrie: el atacante descargó un fichero al señuelo") del 2026-11-14 10:35:21,008Z = 04:35:21 CST, origen `198.51.100.x` por telnet (puerto 2223). Es tráfico real de Internet, no un estímulo del operador.

**No observado por el operador:** las consultas de Discover (apartados 2 y 3). El operador pidió que las ejecutara Claude.

## 2. Consultas equivalentes ejecutadas por Claude contra el Indexer (NO es observación del Dashboard)

Mismos filtros y rangos que las DQL de Discover. Solo demuestra que los datos existen en `wazuh-alerts-*`; no demuestra cómo se renderizan.

### 2.1 Día 5 (hueco de `2026-11-13/d5-7-dashboard.md`) · 13-nov 02:30–03:00 CST

DQL: `agent.name:("ubuntu-lab" or "win11-lab") and rule.id:(5710 or 5712 or 5503 or 60122 or 60109 or 60111)` → **17 eventos**, igual que el cruce con `d5-6-alertas.jsonl`.

| agent.name | rule.id | level | eventos |
|---|---|---|---|
| ubuntu-lab | 5710 | 5 | 7 |
| ubuntu-lab | 5503 | 5 | 4 |
| ubuntu-lab | 5712 | **10** | 1 |
| win11-lab | 60109 | 8 | 2 |
| win11-lab | 60122 | 5 | 2 |
| win11-lab | 60111 | 8 | 1 |

`agent.name` exacto (`ubuntu-lab`, `win11-lab`); 5712 con nivel 10. Las reglas 60160 (2), 60170 (2) y 60110 (1) existen en el índice para esos agentes y rango, pero el DQL no las incluye, así que el Dashboard no debe mostrarlas con ese filtro.

### 2.2 Hoy · 02:30–05:00 CST, `rule.id:(5710 or 60122 or 100300)`

| agent.name | rule.id | level | eventos |
|---|---|---|---|
| ubuntu-lab | 5710 | 5 | 1 (3f) |
| win11-lab | 60122 | 5 | 1 (3g) |
| vm-honeyserver | 100300 | 5 | 96 |

Los 96 de 100300 son eventos de log (varias líneas por sesión), no sesiones. Incluyen 20 generados por la prueba de diagnóstico de Claude (origen `172.19.0.1`, 10:38:55–10:39:27Z), que hay que excluir de cualquier conteo de 3c/TEST-004. Sesiones del operador: ver `f8b-3-alertas.txt`.

### 2.3 Ayer · 13-nov 14:00–16:00 CST (honeypots)

| agent.name | rule.id | level | eventos |
|---|---|---|---|
| vm-honeyserver | 100101 | 5 | 1 |
| vm-honeyserver | 100210 | 8 | 1 |
| vm-honeyserver | 100400 | 3 | 1 |
| vm-honeyserver | 100410 | 8 | **1 (esperado 2)** |
| vm-honeyserver | 100200 | 3 | 64 (6 del 3b-bis + tráfico real de Internet) |
| vm-honeyserver | 100300 | 5 | 144 (incluye el FP del healthcheck anterior a la 100301) |

## 3. Hallazgo: una alerta del Manager no llegó al Indexer

- El Manager registró **2** alertas 100410 (`f8-3-alertas.jsonl`): sqli a las 2026-11-13 20:33:28,854Z y xss a las 20:34:06,864Z. El Indexer solo tiene el **xss**.
- Filebeat registró a las **20:33:31,671Z** un `WARN … Cannot index event` con `illegal_argument_exception` / `max_bytes_length_exceeded_exception`: "bytes can be at most 32766 in length; got 34682". El campo es `data.response_msg.response.message.detection.payload.value` (payload de detección de Tanner).
- Es el **único** `Cannot index event` en los 8 ficheros rotados de Filebeat. No hubo reintento: el 400 de mapeo descarta el evento.
- **Impacto:** el Manager (`alerts.json`, y por tanto la evidencia `f8-3-alertas.jsonl`) conserva la alerta, pero el Dashboard y cualquier consulta al Indexer **no la verán**. Para TEST-001/TEST-006 el ground truth debe medirse contra `alerts.json` o asumir un FN documentado en el Indexer para eventos con payload > 32 766 bytes.
- **No corregido en esta sesión.** Posible mitigación (decisión del operador): limitar o ignorar ese campo en el mapeo/pipeline de Filebeat o truncar el payload en el decoder.

## 4. ISM del índice 2026-11-08

`_ism/add` aplicado (`updated_indices: 1`, `failures: false`); `explain` muestra 4 de 4 índices con `wazuh-alert-retention-policy`. El estado interno del 08-nov estaba en `None` justo tras añadirlo (ISM lo inicializa en su siguiente ciclo). Ver `f8b-5-ism.log`; se reconfirma al cierre.
