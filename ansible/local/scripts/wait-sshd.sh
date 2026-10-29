#!/usr/bin/env bash
# Espera a que los 4 sshd acepten TCP antes de correr Ansible.
set -euo pipefail

targets=(
  "10.50.20.10 22"
  "10.50.40.10 22"
  "10.50.30.10 22"
  "10.50.10.10 22222"
)

for entry in "${targets[@]}"; do
  read -r ip port <<<"$entry"
  ok=0
  for _ in $(seq 1 60); do
    if nc -z -w 2 "$ip" "$port" >/dev/null 2>&1; then
      ok=1
      break
    fi
    sleep 1
  done
  if [ "$ok" -ne 1 ]; then
    echo "wait-sshd: ${ip}:${port} no responde" >&2
    docker compose -f "$(dirname -- "${BASH_SOURCE[0]}")/../docker-compose.yml" ps >&2 || true
    exit 1
  fi
  echo "ok: ${ip}:${port}"
done
