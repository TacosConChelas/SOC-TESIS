#!/usr/bin/env bash
# Prueba del escáner: planta secretos falsos (construidos en runtime, para que
# este script no los contenga literalmente) y exige que el escaneo falle.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ansible_dir="$(cd -- "$here/../.." && pwd)"
repo_root="$(cd -- "$ansible_dir/.." && pwd)"
scan="python3 $ansible_dir/local/scripts/secret-scan.py"
plant="$ansible_dir/local/.selftest-scan.txt"

cleanup() { rm -f "$plant"; }
trap cleanup EXIT

fake_hex="$(printf 'a%.0s' $(seq 1 64))"
fake_psk="psk: ${fake_hex}"
fake_secret="pre_shared_key = ${fake_hex:0:40}"
# Se arma en runtime para que este script no contenga el encabezado PEM.
fake_pem="-----BEGIN OPENSSH ""PRIVATE KEY-----"

expect_fail() {
  local label="$1" content="$2"
  printf '%s\n' "$content" >"$plant"
  if (cd "$repo_root" && $scan >/dev/null 2>&1); then
    echo "FALLA: el escaner no detecto el caso '$label'" >&2
    exit 1
  fi
  echo "ok: detectado '$label'"
}

# Control: el arbol limpio debe pasar (si no, la prueba no vale nada).
if ! (cd "$repo_root" && $scan >/dev/null 2>&1); then
  echo "FALLA: el arbol ya tiene hallazgos; corrige antes de la prueba" >&2
  exit 1
fi
echo "ok: arbol limpio"

expect_fail "asignacion psk" "$fake_psk"
expect_fail "asignacion pre_shared_key" "$fake_secret"
expect_fail "hex64 suelto" "valor=${fake_hex}"
expect_fail "llave privada" "$fake_pem"

echo "secret-scan-selftest: ok (4 casos plantados + control)"
