#!/usr/bin/env bash
# Etapa 4b (E1-5): entrega el PSK a vm-strongswan con managed run command.
# El PSK solo viaja en un body JSON 0600 (borrado con trap) como parámetro
# protegido; nunca en argv. Al terminar se borra el run command.
set -euo pipefail
PSK_FILE=${1:?uso: psk-deliver.sh <archivo PSK 0600>}
RG=${RG:-rg-soc-tesis-lab}; VM=vm-strongswan; NAME=soc-bootstrap-strongswan
DIR=$(cd "$(dirname "$0")" && pwd)

[ "$(stat -c %a "$PSK_FILE")" = 600 ] || { echo "psk-deliver: $PSK_FILE debe ser 0600" >&2; exit 1; }
[ "$(grep -cxE '[0-9a-f]{64}' "$PSK_FILE")" = 1 ] && [ "$(wc -l <"$PSK_FILE")" -le 1 ] ||
  { echo "psk-deliver: el archivo debe tener una sola línea de 64 hex (openssl rand -hex 32)" >&2; exit 1; }

umask 077
body=$(mktemp); view=$(mktemp); trap 'rm -f "$body" "$view"' EXIT
loc=$(az vm show -g "$RG" -n "$VM" --query location -o tsv)
python3 - "$PSK_FILE" "$DIR/bootstrap-strongswan.sh" "$body" "$loc" <<'EOF'
import json, sys
clave = open(sys.argv[1]).read().strip()
script = open(sys.argv[2]).read()
json.dump({"location": sys.argv[4], "properties": {
    "source": {"script": script},
    "protectedParameters": [{"name": "PSK", "value": clave}],
    "asyncExecution": False, "timeoutInSeconds": 600}}, open(sys.argv[3], "w"))
EOF

api=$(az provider show -n Microsoft.Compute \
  --query "resourceTypes[?resourceType=='virtualMachines/runCommands'].apiVersions[0]" -o tsv)
sub=$(az account show --query id -o tsv)
az rest --method put -o none --body @"$body" \
  --url "https://management.azure.com/subscriptions/$sub/resourceGroups/$RG/providers/Microsoft.Compute/virtualMachines/$VM/runCommands/$NAME?api-version=$api"
rm -f "$body"

st=
for _ in $(seq 60); do
  st=$(az vm run-command show -g "$RG" --vm-name "$VM" -n "$NAME" --instance-view \
       --query 'instanceView.executionState' -o tsv 2>/dev/null || true)
  case "$st" in Succeeded|Failed|TimedOut|Canceled) break;; esac
  sleep 10
done

az vm run-command show -g "$RG" --vm-name "$VM" -n "$NAME" --instance-view -o json >"$view"
leak=0; grep -qFf "$PSK_FILE" "$view" && leak=1
az vm run-command show -g "$RG" --vm-name "$VM" -n "$NAME" --instance-view \
  --query 'instanceView.{estado:executionState,exit:exitCode,salida:output,error:error}' -o yamlc
az vm run-command delete -g "$RG" --vm-name "$VM" -n "$NAME" --yes
echo "psk-local:  $(tr -d '\n' <"$PSK_FILE" | sha256sum | cut -c1-12)"

[ "$leak" = 0 ] || { echo "psk-deliver: EL PSK APARECE EN LA INSTANCE VIEW; rotarlo" >&2; exit 1; }
[ "$st" = Succeeded ] || { echo "psk-deliver: run command en estado '$st'" >&2; exit 1; }
echo "psk-deliver: ok"
