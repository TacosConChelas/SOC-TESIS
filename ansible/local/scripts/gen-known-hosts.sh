#!/usr/bin/env bash
# Simula la Etapa 4a: huellas de host a un known_hosts desechable.
# En Azure se obtienen por run-command; aqui, por ssh-keyscan a los contenedores.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
local_dir="$(cd -- "$here/.." && pwd)"
out="$local_dir/.known_hosts"
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

hosts=(
  "10.50.20.10 22"
  "10.50.40.10 22"
  "10.50.30.10 22"
  "10.50.10.10 22222"
)

: >"$tmp"

for entry in "${hosts[@]}"; do
  read -r ip port <<<"$entry"
  ok=0
  for _ in $(seq 1 30); do
    if ssh-keyscan -T 3 -p "$port" "$ip" 2>/dev/null | grep -v '^#' >>"$tmp" \
      && grep -q -- "$ip" "$tmp"; then
      ok=1
      break
    fi
    sleep 1
  done
  if [ "$ok" -ne 1 ]; then
    echo "gen-known-hosts: sin respuesta de ${ip}:${port}" >&2
    exit 1
  fi
done

grep -v '^#' "$tmp" | sort -u >"$out"
chmod 0600 "$out"

expected=4
got="$(cut -d' ' -f1 "$out" | sort -u | wc -l)"
if [ "$got" -ne "$expected" ]; then
  echo "known_hosts incompleto: $got/$expected hosts" >&2
  cat "$out" >&2
  exit 1
fi

echo "known_hosts: $out ($got hosts, $(wc -l <"$out") claves)"
