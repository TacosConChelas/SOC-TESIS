#!/usr/bin/env bash
# Verifica el cierre de egreso simulando la Etapa 7 (E1-6).
# Destinos fuera de Azure para no dar falsos positivos, con timeout corto.
set -euo pipefail

net="soc-local-install"
containers=(
  soc-local-strongswan
  soc-local-wazuh
  soc-local-logrelay
  soc-local-honeyserver
)
fail=0

for c in "${containers[@]}"; do
  if docker inspect -f '{{if index .NetworkSettings.Networks "'"$net"'"}}yes{{else}}no{{end}}' "$c" | grep -q yes; then
    echo "FALLA: $c sigue conectado a $net (egreso abierto)" >&2
    fail=1
  fi
done

probe() {
  local c="$1" url="$2"
  if timeout 20 docker exec "$c" curl -m5 -sf -o /dev/null "$url"; then
    echo "FALLA: $c alcanzo $url con el egreso cerrado" >&2
    return 1
  fi
  echo "ok: $c no alcanza $url"
}

if ! probe soc-local-honeyserver http://1.1.1.1; then fail=1; fi
if ! probe soc-local-honeyserver https://example.com; then fail=1; fi
if ! probe soc-local-strongswan http://1.1.1.1; then fail=1; fi

if [ "$fail" -ne 0 ]; then
  echo "netcheck: el egreso NO esta cerrado" >&2
  exit 1
fi

echo "netcheck: egreso cerrado en los 4 contenedores"
