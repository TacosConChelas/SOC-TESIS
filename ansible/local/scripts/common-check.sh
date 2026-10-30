#!/usr/bin/env bash
# Verifica el rol common en el ensayo local (spec 2026-10-29-common-role-design.md §4).
# Requiere los contenedores arriba y convergidos (make rehearse).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
local_dir="$(cd "$here/.." && pwd)"
known="$local_dir/.known_hosts"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }

# nombre contenedor ip puerto
vms=(
  "strongswan soc-local-strongswan 10.50.20.10 22"
  "wazuh soc-local-wazuh 10.50.40.10 22"
  "logrelay soc-local-logrelay 10.50.30.10 22"
  "honeyserver soc-local-honeyserver 10.50.10.10 22222"
)

for entry in "${vms[@]}"; do
  read -r name ctr ip port <<<"$entry"

  # 1. Timers de apt enmascarados e inactivos.
  for t in apt-daily.timer apt-daily-upgrade.timer; do
    state="$(docker exec "$ctr" systemctl is-enabled "$t" 2>/dev/null || true)"
    if [ "$state" = masked ] && ! docker exec "$ctr" systemctl is-active --quiet "$t"; then
      good "$name: $t enmascarado e inactivo"
    else
      bad "$name: $t no esta enmascarado/inactivo (is-enabled='$state')"
    fi
  done

  # 2. apt sin periodos automaticos. La imagen de contenedor ya desactiva el
  # periodo, asi que solo el archivo del rol prueba que el rol actuo.
  conf=/etc/apt/apt.conf.d/99-soc-no-auto.conf
  if docker exec "$ctr" grep -qx 'APT::Periodic::Unattended-Upgrade "0";' "$conf" 2>/dev/null \
     && docker exec "$ctr" grep -qx 'APT::Periodic::Update-Package-Lists "0";' "$conf" 2>/dev/null \
     && docker exec "$ctr" grep -qx 'APT::Periodic::Download-Upgradeable-Packages "0";' "$conf" 2>/dev/null; then
    good "$name: $conf con las 3 lineas"
  else
    bad "$name: falta $conf o no tiene las 3 lineas"
  fi
  dump="$(docker exec "$ctr" apt-config dump 2>/dev/null || true)"
  if grep -q '^APT::Periodic::Unattended-Upgrade "0";' <<<"$dump" \
     && grep -q '^APT::Periodic::Update-Package-Lists "0";' <<<"$dump"; then
    good "$name: apt-config dump sin actualizacion automatica"
  else
    bad "$name: apt-config dump aun permite actualizacion automatica"
  fi

  # 3. Configuracion efectiva de sshd.
  eff="$(docker exec "$ctr" /usr/sbin/sshd -T 2>/dev/null || true)"
  for want in "permitrootlogin no" "passwordauthentication no" \
              "kbdinteractiveauthentication no" "maxauthtries 3" "port $port"; do
    if grep -qx "$want" <<<"$eff"; then good "$name: sshd -T '$want'"; else bad "$name: sshd -T no tiene '$want'"; fi
  done

  # 4. El demonio EN EJECUCION ya no ofrece contrasena ni teclado interactivo.
  out="$(ssh -o BatchMode=yes -o PreferredAuthentications=password -o PubkeyAuthentication=no \
            -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known" -o GlobalKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 -p "$port" "soctesis@$ip" true 2>&1 || true)"
  if grep -Fq 'Permission denied (publickey)' <<<"$out"; then
    good "$name: el demonio solo ofrece publickey"
  else
    bad "$name: el demonio ofrece mas que publickey (salida: $out)"
  fi

  # 5. Zona horaria.
  tz="$(docker exec "$ctr" timedatectl show -p Timezone --value 2>/dev/null || true)"
  if [ "$tz" = UTC ]; then good "$name: zona horaria UTC"; else bad "$name: zona horaria '$tz', se esperaba UTC"; fi
done

if [ "$fail" -ne 0 ]; then
  echo "common-check: FALLA" >&2
  exit 1
fi
echo "common-check: ok"
