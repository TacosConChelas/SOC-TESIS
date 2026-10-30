#!/usr/bin/env bash
# Fixture del ARNES (no del rol): instala wazuh-agent en honeyserver y lo enrola por el relay (D4).
# El rol `honeypot` hara esto de verdad mas adelante. Requiere el egreso abierto.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
defaults="$here/../../roles/wazuh/defaults/main.yml"
secrets="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
ctr=soc-local-honeyserver
relay_ctr=soc-local-logrelay
relay_ip=10.50.30.10

version="$(sed -n 's/^wazuh_expected_version:[[:space:]]*"\([^"]*\)".*/\1/p' "$defaults" | head -n1)"
[ -n "$version" ] || { echo "FALLA: wazuh_expected_version no esta definida en $defaults" >&2; exit 1; }
[ -s "$secrets/authd.pass" ] || { echo "FALLA: falta $secrets/authd.pass (make wazuh-secrets)" >&2; exit 1; }
docker exec "$relay_ctr" systemctl is-active --quiet nginx \
  || { echo "FALLA: nginx del relay no esta activo (corre make rehearse antes)" >&2; exit 1; }

if docker exec "$ctr" dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "wazuh-agent-fixture: wazuh-agent ya instalado en honeyserver"
else
  env_file="$(mktemp)"
  trap 'rm -f "$env_file"' EXIT
  chmod 600 "$env_file"
  printf 'WAZUH_MANAGER=%s\nWAZUH_REGISTRATION_PASSWORD=%s\n' "$relay_ip" "$(tr -d '\n' <"$secrets/authd.pass")" >"$env_file"

  docker exec "$ctr" sh -c '
    set -e
    apt-get update -qq
    apt-get install -y -qq gnupg >/dev/null
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH \
      | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
    chmod 644 /usr/share/keyrings/wazuh.gpg
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
      >/etc/apt/sources.list.d/wazuh.list
    apt-get update -qq
  '
  docker exec --env-file "$env_file" "$ctr" sh -c "apt-get install -y -qq wazuh-agent=${version}-1"
fi

docker exec "$ctr" systemctl enable --now wazuh-agent
echo "wazuh-agent-fixture: ok (agente ${version} apuntando al relay ${relay_ip})"
