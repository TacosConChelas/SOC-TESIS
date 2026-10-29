#!/usr/bin/env bash
# Lee un log de ansible-playbook y valida el PLAY RECAP.
#   recap-check.sh <log> changed     -> exige changed > 0, failed=0, unreachable=0
#   recap-check.sh <log> nochange    -> exige changed = 0, failed=0, unreachable=0
set -euo pipefail

log="${1:?uso: recap-check.sh LOG changed|nochange}"
mode="${2:?uso: recap-check.sh LOG changed|nochange}"

if [ ! -s "$log" ]; then
  echo "recap-check: log vacio: $log" >&2
  exit 1
fi

read -r changed failed unreachable <<<"$(
  awk '
    /changed=/ && /failed=/ && /unreachable=/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^changed=/)     { gsub(/changed=/, "", $i);     c += $i }
        if ($i ~ /^failed=/)      { gsub(/failed=/, "", $i);      f += $i }
        if ($i ~ /^unreachable=/) { gsub(/unreachable=/, "", $i); u += $i }
      }
    }
    END { print c + 0, f + 0, u + 0 }
  ' "$log"
)"

if [ "$failed" -ne 0 ] || [ "$unreachable" -ne 0 ]; then
  echo "recap-check: failed=$failed unreachable=$unreachable (log: $log)" >&2
  exit 1
fi

case "$mode" in
  changed)
    if [ "$changed" -eq 0 ]; then
      echo "recap-check: la primera pasada no aplico cambios (log: $log)" >&2
      exit 1
    fi
    ;;
  nochange)
    if [ "$changed" -ne 0 ]; then
      echo "recap-check: la pasada no es idempotente, changed=$changed (log: $log)" >&2
      exit 1
    fi
    ;;
  *)
    echo "recap-check: modo desconocido: $mode" >&2
    exit 2
    ;;
esac

echo "recap-check: ok ($mode) changed=$changed failed=0 unreachable=0"
