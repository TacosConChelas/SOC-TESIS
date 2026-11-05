#!/usr/bin/env bash
# Envejece la caché de apt en los 4 contenedores y verifica el mtime.
# Se usa desde make stage9-rehearse antes de la pasada completa sin tags.
# Falla si el mtime de algún directorio no quedó realmente viejo (< ahora - 90 min).
set -euo pipefail

containers=(
  soc-local-strongswan
  soc-local-wazuh
  soc-local-logrelay
  soc-local-honeyserver
)

fail=0
threshold=$(( $(date +%s) - 90 * 60 ))   # hace 90 min; pedimos -2h, margen holgado

for c in "${containers[@]}"; do
  # Envejecer el directorio de listas (siempre existe)
  docker exec "$c" touch -d '-2 hours' /var/lib/apt/lists
  # Envejecer el stamp si existe (no existe en estos contenedores, pero queda
  # preparado para un host real con unattended-upgrades instalado)
  docker exec "$c" bash -c \
    'f=/var/lib/apt/periodic/update-success-stamp; [ -e "$f" ] && touch -d "-2 hours" "$f" || true'

  # Verificar mtime
  mtime="$(docker exec "$c" stat -c '%Y' /var/lib/apt/lists)"
  if [ "$mtime" -lt "$threshold" ]; then
    echo "ok: $c /var/lib/apt/lists mtime=$(date -d "@$mtime" +%T) (hace $(( ($(date +%s) - mtime) / 60 )) min)"
  else
    echo "FALLA: $c /var/lib/apt/lists mtime demasiado reciente ($(date -d "@$mtime" +%T))" >&2
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "stage9-rehearse-apt-age: FALLA" >&2
  exit 1
fi
echo "stage9-rehearse-apt-age: ok (caché envejecida en los 4 contenedores)"
