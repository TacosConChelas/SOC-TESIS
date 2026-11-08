#!/usr/bin/env bash
# Gate de autorizacion de la Etapa 1. NO ejecuta apply: solo registra el
# sha256 del plan autorizado para que la Etapa 2 compruebe que aplica ese.
set -euo pipefail

PLAN=/tmp/tfplan
AUTH=/tmp/tfplan.authorized
PHRASE='AUTORIZO terraform apply de /tmp/tfplan'

if [ ! -f "$PLAN" ]; then
  echo "gate-apply: no existe $PLAN; corre 'make plan' primero" >&2
  exit 1
fi

if ! { exec 3</dev/tty; } 2>/dev/null; then
  echo "gate-apply: sin TTY; el gate exige autorizacion interactiva" >&2
  exit 1
fi

printf 'Frase exacta: %s\n' "$PHRASE" >&2
printf 'Escribe la frase: ' >&2
if ! IFS= read -r answer <&3; then
  printf '\n' >&2
  echo "gate-apply: no se pudo leer la autorizacion" >&2
  exit 1
fi
exec 3<&-

if [ "$answer" != "$PHRASE" ]; then
  echo "gate-apply: la frase no coincide; apply NO autorizado" >&2
  exit 1
fi

umask 077
sha256sum "$PLAN" >"$AUTH"
chmod 600 "$AUTH"
echo "gate-apply: autorizado; sha256 en $AUTH (0600). apply NO ejecutado"
