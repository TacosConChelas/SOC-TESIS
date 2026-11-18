# <TEST-00X> · <RUN-k_AAAAMMDDTHHMMSSZ> · Precondiciones

## Prueba

| Campo | Valor |
|---|---|
| Escenario | <TEST-00X — nombre (doc 07 §3)> |
| Objetivo | <qué capacidad del SOC se evalúa> |
| Host de origen | <192.168.1.73 / .74 / .75> |
| Objetivo de red | <honeyserver:puerto / endpoint> |
| Ventana prevista (UTC) | <inicio> → <fin> |
| Operador | <nombre> |

## Criterio de aceptación (fijado antes de ejecutar, OMI-08)

- <p. ej.: ≥ 95 % de las acciones positivas con alerta (TP), 0 FN en reglas de nivel ≥ 8, MTTD p95 ≤ 60 s>

## Reglas esperadas

| Acción | Fuente | `rule.id` | Nivel |
|---|---|---|---|
| <acción> | <cowrie/dionaea/mailoney/tanner/windows/ubuntu> | <id> | <n> |

## Estado del entorno (pegar salidas)

- Baseline: commit `<git rev-parse --short HEAD>`; `local_rules.xml` sha256 `<…>`.
- Túnel: `swanctl --list-sas` → <ESTABLISHED/INSTALLED, hora>.
- Agentes: `agent_control -l` → <honeyserver / ubuntu-lab / win11-lab Active>.
- Honeypots: <7/7 healthy, RestartCount>.
- Relojes (offset > 500 ms invalida MTTD): Azure `chronyc tracking` <…>; Ubuntu `timedatectl` <…>; Windows `w32tm /query /status` <…>.
- Recursos al inicio (wazuh): `free -m` <…>; `df -h /var/lib/wazuh-indexer` <…>.
