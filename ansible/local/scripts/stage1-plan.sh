#!/usr/bin/env bash
# Etapa 1 (parte AUTO): plan guardado en /tmp/tfplan + checks del plan.
# Nunca imprime el contenido del plan ni rutas del home. No hace apply.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PY=${PY:-python3}
TF_DIR=${TF_DIR:?falta TF_DIR}

PLAN=/tmp/tfplan
JSON=/tmp/tfplan.json
LOG=/tmp/tfplan.log
AUTH=/tmp/tfplan.authorized

if [ ! -d "$TF_DIR/.terraform/providers" ]; then
  echo "plan: falta $TF_DIR/.terraform; corre 'terraform init' ahi una vez (este script no lo hace para no tocar el repo)" >&2
  exit 1
fi

umask 077
trap 'rm -f "$JSON" "$LOG"' EXIT

# Un plan nuevo invalida cualquier autorizacion anterior.
rm -f "$PLAN" "$AUTH"

if ! terraform -chdir="$TF_DIR" plan -input=false -lock=false \
    -var maintenance_egress=false -out="$PLAN" >"$LOG" 2>&1; then
  if grep -qiE 'admin_ssh_public_key_path|no file exists|no such file' "$LOG"; then
    echo "plan: FALLA. Falta o no se puede leer la llave publica SSH (admin_ssh_public_key_path en terraform.tfvars); no se imprime la ruta." >&2
  else
    echo "plan: FALLA; salida redactada:" >&2
    sed -E 's#(/home|/Users)/[^ "]*#<home>/<ruta>#g' "$LOG" | tail -n 15 >&2
  fi
  exit 1
fi

if ! terraform -chdir="$TF_DIR" show -json "$PLAN" >"$JSON"; then
  echo "plan: FALLA (no se pudo derivar el JSON del plan)" >&2
  exit 1
fi

"$PY" "$SCRIPT_DIR/plan-check.py" "$JSON"
echo "plan: ok (/tmp/tfplan, 0600); contenido no impreso"
