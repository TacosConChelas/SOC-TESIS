#!/usr/bin/env bash
# Secretos DESECHABLES del ensayo local, fuera del repo (la guarda del rol wazuh lo exige).
set -euo pipefail

dir="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
umask 077
mkdir -p "$dir"
chmod 700 "$dir"

if [ ! -s "$dir/authd.pass" ]; then
  openssl rand -base64 32 >"$dir/authd.pass"
fi
chmod 600 "$dir/authd.pass"
echo "wazuh-secrets: ok ($dir)"
