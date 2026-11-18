# Plantilla de RUN (Fase 9)

Estructura de doc 19 §1. Para cada ejecución de un TEST:

```bash
T=TEST-00X; RUN="RUN-<k>_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "evidence/tests/$T/$RUN"/{03-raw,05-metricas}
cp evidence/tests/_plantilla/{00-precondiciones.md,01-ground-truth.jsonl,02-comandos.txt,06-resultado.md} "evidence/tests/$T/$RUN/"
```

| Archivo | Cuándo se rellena | ¿Git? |
|---|---|---|
| `00-precondiciones.md` | **Antes** de la primera acción (criterio de aceptación incluido) | sí |
| `01-ground-truth.jsonl` | Una línea por acción, en el momento | sí |
| `02-comandos.txt` | Comando exacto, host de origen y exit code | sí |
| `03-raw/` | Extractos crudos de honeypot, endpoint y Relay de la ventana | **no** |
| `04-alertas.json` | Export de `wazuh-alerts-*` de la ventana (doc 19 §4) | **no** |
| `05-metricas/` | `vmstat`/`sar`, EPS, cola del agente | **no** |
| `06-resultado.md` | Al cerrar: TP/FP/FN, MTTD, KPIs, veredicto | sí |

Cierre de la RUN (doc 19 §5), antes de apagar las VMs:

```bash
cd "evidence/tests/$T/$RUN" && find . -type f ! -name MANIFEST.sha256 -print0 | sort -z | xargs -0 sha256sum > MANIFEST.sha256
sha256sum MANIFEST.sha256   # → línea en evidence/tests/INDEX.md
bash terraform/evidence/evidence-sync.sh "evidence/tests/$T/$RUN" "tests/$T/$RUN"
```

Una RUN subida no se edita: las correcciones van en una RUN nueva o en `06-resultado.md` con nota de cambio y MANIFEST nuevo.
