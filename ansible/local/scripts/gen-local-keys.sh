#!/usr/bin/env bash
# Llave SSH desechable para el ensayo local. Nunca sale del repo ignorado.
set -euo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
dir="$(cd -- "$here/.." && pwd)/.keys"

mkdir -p "$dir"
chmod 0700 "$dir"

if [ ! -f "$dir/local_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'soc-local-test' -f "$dir/local_ed25519"
fi

chmod 0600 "$dir/local_ed25519"
chmod 0644 "$dir/local_ed25519.pub"
echo "llave local: $dir/local_ed25519"
