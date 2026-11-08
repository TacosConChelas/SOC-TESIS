#!/usr/bin/env bash
# Etapa 4a (E1-4): known_hosts de las 4 VMs leído por run-command (no depende
# de la red ni del túnel). Sin secretos: solo claves públicas de host.
set -euo pipefail

# Del mensaje de run-command, solo la clave ed25519 dentro de [stdout].
extract() { awk '/^\[stdout\]/{f=1;next} /^\[stderr\]/{f=0} f && $1=="ssh-ed25519"{print $1" "$2}'; }

if [ "${1:-}" = --selftest ]; then
  got=$(printf 'Enable succeeded: \n[stdout]\nssh-ed25519 AAAAC3x root@vm\n\n[stderr]\nssh-ed25519 MALA\n' | extract)
  [ "$got" = "ssh-ed25519 AAAAC3x" ] || { echo "host-keys selftest: FALLA ($got)" >&2; exit 1; }
  echo "host-keys selftest: ok"; exit 0
fi

OUT=${1:?uso: host-keys.sh <known_hosts fuera del repo> | --selftest}
RG=${RG:-rg-soc-tesis-lab}
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
case "$(realpath -m "$OUT")" in "$repo"/*) echo "host-keys: $OUT está dentro del repo" >&2; exit 1;; esac

declare -A HOSTS=(
  [vm-strongswan]=10.50.20.10
  [vm-wazuh]=10.50.40.10
  [vm-logrelay]=10.50.30.10
  [vm-honeyserver]='[10.50.10.10]:22222'
)
umask 077
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
for vm in vm-strongswan vm-wazuh vm-logrelay vm-honeyserver; do
  key=$(az vm run-command invoke -g "$RG" -n "$vm" --command-id RunShellScript \
        --scripts 'cat /etc/ssh/ssh_host_ed25519_key.pub' \
        --query 'value[0].message' -o tsv | extract)
  [ "$(printf '%s\n' "$key" | grep -c .)" = 1 ] || { echo "host-keys: $vm no devolvió una única clave ed25519" >&2; exit 1; }
  printf '%s %s\n' "${HOSTS[$vm]}" "$key" >>"$tmp"
  printf '%-15s %s\n' "$vm" "$(printf '%s %s\n' "${HOSTS[$vm]}" "$key" | ssh-keygen -lf - | awk '{print $2}')"
done
mv "$tmp" "$OUT"; trap - EXIT
echo "host-keys: 4 claves en $OUT"
