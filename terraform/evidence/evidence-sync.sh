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
DIR=$(realpath "$DIR")   # absoluta: más abajo se compara desde otra carpeta
SECRETS=$HOME/soc-tesis-secrets   # fijo: la lista de secretos no la elige el entorno
TF=$(cd "$(dirname "$0")" && pwd)

m=$(manifest "$DIR") || { echo "evidence-sync: $DIR no tiene MANIFEST.sha256 ni SHA256SUMS" >&2; exit 1; }
(cd "$DIR" && sha256sum -c --quiet "$m") || { echo "evidence-sync: el manifiesto local de $DIR no cuadra" >&2; exit 1; }

# Enlaces y comprimidos esconderían contenido a la higiene: se rechazan antes de subir.
if [ -n "$(find "$DIR" \( -type l -o -iname '*.tar' -o -iname '*.tar.*' -o -iname '*.tgz' -o -iname '*.gz' -o -iname '*.zip' -o -iname '*.7z' \) -print -quit)" ]; then
  echo "evidence-sync: $DIR contiene enlaces simbólicos o archivos comprimidos; no se sube" >&2; exit 1
fi
# ponytail: grep literal; no ve un secreto recodificado (base64, hex). Añadir esas
# variantes si alguna vez se sube algo que no sea texto plano de logs.
for s in "$SECRETS/ipsec/psk.hex" "$SECRETS/wazuh/authd.pass" "$SECRETS/ssh/id_ed25519"; do
  [ -s "$s" ] || { echo "evidence-sync: falta $s para la comprobación de higiene" >&2; exit 1; }
  if grep -rqFf "$s" "$DIR"; then
    echo "evidence-sync: $DIR contiene un secreto del proyecto; no se sube" >&2; exit 1
  fi
done

# IDs de Azure (suscripción, tenant, objeto) escondidos en base64, p. ej. el id de
# data.azurerm_client_config: la redacción por regex de GUID no los ve.
guid='[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
while read -r tok; do
  if printf '%s' "$tok" | base64 -d 2>/dev/null | grep -aqE "$guid"; then
    echo "evidence-sync: $DIR contiene un ID de Azure codificado en base64; redactarlo antes de subir" >&2; exit 1
  fi
done < <(grep -rhoE '[A-Za-z0-9+/]{48,}={0,2}' "$DIR" || true)

ACCOUNT=$(terraform -chdir="$TF" output -raw storage_account_name)
CONTAINER=$(terraform -chdir="$TF" output -raw container_name)

az storage blob upload-batch --auth-mode login --account-name "$ACCOUNT" \
  -d "$CONTAINER" --destination-path "$PREFIX" -s "$DIR" --overwrite false -o none

out=$(mktemp -d); trap 'rm -rf "$out"' EXIT
az storage blob download-batch --auth-mode login --account-name "$ACCOUNT" \
  -s "$CONTAINER" --pattern "$PREFIX/*" -d "$out" -o none
# Contra el manifiesto LOCAL (no el descargado) y con el mismo conjunto de archivos.
cmp -s "$DIR/$m" "$out/$PREFIX/$m" ||
  { echo "evidence-sync: el manifiesto restaurado de $PREFIX difiere del local" >&2; exit 1; }
(cd "$out/$PREFIX" && sha256sum -c --quiet "$DIR/$m") ||
  { echo "evidence-sync: la copia restaurada de $PREFIX no cuadra con $m" >&2; exit 1; }
diff <(cd "$out/$PREFIX" && find . -type f | sort) <(cd "$DIR" && find . -type f | sort) >/dev/null ||
  { echo "evidence-sync: $PREFIX en el Blob no tiene los mismos archivos que $DIR" >&2; exit 1; }

# "ok" = el Blob contiene exactamente esta carpeta (recién subida o ya presente:
# --overwrite false e inmutabilidad hacen que una 2.ª subida no escriba nada).
echo "evidence-sync: ok $PREFIX ($(sha256sum "$DIR/$m" | cut -c1-12) $m)"
