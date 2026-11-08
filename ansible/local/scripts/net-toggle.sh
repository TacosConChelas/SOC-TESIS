#!/usr/bin/env bash
# Simula la ventana de egreso (Etapas 3 y 7 de PIPELINE.md).
#   install  -> conecta los contenedores a la red con salida a Internet
#   operate  -> los desconecta; solo queda la red internal (sin egreso)
#   status   -> muestra las redes de cada contenedor
set -euo pipefail

action="${1:-status}"
net="soc-local-install"
containers=(
  soc-local-strongswan
  soc-local-wazuh
  soc-local-logrelay
  soc-local-honeyserver
)

connected() {
  docker inspect -f '{{if index .NetworkSettings.Networks "'"$net"'"}}yes{{else}}no{{end}}' "$1"
}

case "$action" in
  install)
    for c in "${containers[@]}"; do
      if [ "$(connected "$c")" = "yes" ]; then
        echo "$c: ya conectado a $net"
      else
        docker network connect --gw-priority 10 "$net" "$c"
        echo "$c: conectado a $net (egreso abierto)"
      fi
    done
    ;;
  operate)
    for c in "${containers[@]}"; do
      if [ "$(connected "$c")" = "yes" ]; then
        docker network disconnect -f "$net" "$c"
        echo "$c: desconectado de $net (egreso cerrado)"
      else
        echo "$c: ya estaba sin $net"
      fi
    done
    ;;
  status)
    for c in "${containers[@]}"; do
      printf '%-24s %s\n' "$c" "$(docker inspect -f '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}' "$c")"
    done
    ;;
  *)
    echo "uso: $0 {install|operate|status}" >&2
    exit 2
    ;;
esac
