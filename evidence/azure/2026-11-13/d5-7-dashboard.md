# D5-7 · Confirmación del Dashboard (Fase 4.5)

## Comprobación

- **Fecha de este registro:** 2026-11-13 03:32 CST (09:32 UTC).
- **Estado:** **pendiente de las notas del operador.** En esta sesión no se
  abrió el Dashboard (Kibana de Wazuh) y el operador no entregó sus
  observaciones; abajo queda el hueco marcado, sin rellenar.
- **Alcance de lo que sí se verificó aquí:** la consulta DQL exacta y el cruce
  con `d5-6-alertas.jsonl` (evidencia ya capturada por el Manager).

## Consulta

| Parámetro | Valor |
|---|---|
| Índice | `wazuh-alerts-*` |
| Rango | Last 1 hour |
| DQL | `agent.name:("ubuntu-lab" or "win11-lab") and rule.id:(5710 or 5712 or 5503 or 60122 or 60109 or 60111)` |

## Lo observado por el operador

<<NOTAS DEL OPERADOR: alertas por agente, ¿agent.name correcto?, rule.id vistos, ¿5712 nivel 10?>>

> Pendiente. No se transcribe nada porque no hubo observación del operador en
> esta sesión; este bloque debe completarse con lo que el operador vea en el
> Dashboard, copiado literalmente.

## Cruce con `d5-6-alertas.jsonl`

El fichero tiene 22 líneas (eventos benignos de D5-6, 2026-11-13
08:40:30.772 → 08:44:13.018 UTC = 02:40:30 → 02:44:13 CST). Aplicando el mismo
filtro del DQL (agente y `rule.id`) quedan **17 líneas**:

| agent.name | rule.id | level | eventos |
|---|---|---|---|
| ubuntu-lab | 5503 | 5 | 4 |
| ubuntu-lab | 5710 | 5 | 7 |
| ubuntu-lab | 5712 | **10** | 1 |
| win11-lab | 60109 | 8 | 2 |
| win11-lab | 60111 | 8 | 1 |
| win11-lab | 60122 | 5 | 2 |

### Coincidencias

- Los seis `rule.id` del DQL existen en `alerts.jsonl` para esos dos agentes:
  5710, 5712, 5503 (ubuntu-lab) y 60122, 60109, 60111 (win11-lab).
- `agent.name` de los eventos es exactamente `ubuntu-lab` y `win11-lab`, que es
  lo que el DQL espera; no aparecen con el nombre del host Windows ni con la IP.
- 5712 aparece con `level: 10`, tal como se espera de la regla de fuerza bruta.

### Diferencias / ruido

- `alerts.jsonl` contiene **5 líneas más (22 − 17)** que el DQL deja fuera por
  `rule.id`: 60160 (2 eventos, 4728/4729), 60110 (1, 4738) y 60170 (2,
  4732/4733). Son parte del mismo ejercicio de D5-6 pero **no** están en la
  lista del DQL, así que el Dashboard no debería mostrarlas. Si el operador las
  ve, es señal de que el filtro no se aplicó como se creyó.
- `rule.id 60109` cubre dos `eventID` distintos (4722 y 4720): dos eventos con
  el mismo `rule.id`, no un duplicado.
- **Ventana temporal:** con "Last 1 hour" los 17 eventos (02:40–02:44 CST) solo
  son visibles hasta ~03:44 CST. Una comprobación posterior a esa hora debe
  ampliar el rango; si se hace con "Last 1 hour" y no aparece nada, no es una
  discrepancia con `alerts.jsonl`.

## Nombres de cuenta

En `alerts.jsonl` no hay nombres de cuenta reales del operador; los `srcuser`
del ejercicio son `nouser` y `nouser2` (usuarios inexistentes usados a
propósito). No hay nada que sustituir por `<oper>`.
Confirmacion del operador (2026-11-13, tras d5-7): el operador accedio al Dashboard y confirmo la verificacion visual de las alertas; no aporto conteos numericos.
