#!/usr/bin/env bash
# Fase 7 (doc 19 §5-§6): sube una carpeta de evidencia al Blob y comprueba
# que se restaura con su manifiesto. Sin claves de cuenta: --auth-mode login.
# Lo subido queda inmutable 90 días: por eso se verifica TODO antes de subir.
set -euo pipefail

# Imprime el nombre del manifiesto de la carpeta; falla si no hay ninguno.
manifest() {
  local m
  for m in MANIFEST.sha256 SHA256SUMS; do
    [ -f "$1/$m" ] && { echo "$m"; return 0; }
  done
  return 1
}

if [ "${1:-}" = --selftest ]; then
  t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
  if manifest "$t" >/dev/null; then echo "evidence-sync selftest: FALLA (carpeta sin manifiesto)" >&2; exit 1; fi
  touch "$t/SHA256SUMS"
  [ "$(manifest "$t")" = SHA256SUMS ] || { echo "evidence-sync selftest: FALLA (SHA256SUMS)" >&2; exit 1; }
  touch "$t/MANIFEST.sha256"
  [ "$(manifest "$t")" = MANIFEST.sha256 ] || { echo "evidence-sync selftest: FALLA (prioridad de MANIFEST)" >&2; exit 1; }
  echo "evidence-sync selftest: ok"; exit 0
fi

DIR=${1:?uso: evidence-sync.sh <carpeta> <prefijo en el Blob> | --selftest}
PREFIX=${2:?falta el prefijo, p. ej. azure/2026-11-09}
SECRETS=${SECRETS:-$HOME/soc-tesis-secrets}
TF=$(cd "$(dirname "$0")" && pwd)

m=$(manifest "$DIR") || { echo "evidence-sync: $DIR no tiene MANIFEST.sha256 ni SHA256SUMS" >&2; exit 1; }
(cd "$DIR" && sha256sum -c --quiet "$m") || { echo "evidence-sync: el manifiesto local de $DIR no cuadra" >&2; exit 1; }

for s in "$SECRETS/ipsec/psk.hex" "$SECRETS/wazuh/authd.pass"; do
  [ -s "$s" ] || { echo "evidence-sync: falta $s para la comprobación de higiene" >&2; exit 1; }
  if grep -rqFf "$s" "$DIR"; then
    echo "evidence-sync: $DIR contiene un secreto del proyecto; no se sube" >&2; exit 1
  fi
done

ACCOUNT=$(terraform -chdir="$TF" output -raw storage_account_name)
CONTAINER=$(terraform -chdir="$TF" output -raw container_name)

az storage blob upload-batch --auth-mode login --account-name "$ACCOUNT" \
  -d "$CONTAINER" --destination-path "$PREFIX" -s "$DIR" --overwrite false -o none

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
az storage blob download-batch --auth-mode login --account-name "$ACCOUNT" \
  -s "$CONTAINER" --pattern "$PREFIX/*" -d "$out" -o none
(cd "$out/$PREFIX" && sha256sum -c --quiet "$m") ||
  { echo "evidence-sync: la copia restaurada de $PREFIX no cuadra con $m" >&2; exit 1; }

echo "evidence-sync: ok $PREFIX ($(sha256sum "$DIR/$m" | cut -c1-12) $m)"
