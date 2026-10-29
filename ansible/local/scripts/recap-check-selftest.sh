#!/usr/bin/env bash
# Prueba recap-check.sh con recaps sinteticos: cada modo debe aceptar y rechazar.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# expect <rc_esperado> <modo> <changed> <failed> <unreachable>
expect() {
  printf 'PLAY RECAP *****\nhost1 : ok=3 changed=%s unreachable=%s failed=%s skipped=0 rescued=0 ignored=0\n' \
    "$3" "$5" "$4" >"$tmp/log"
  local rc=0
  bash "$here/recap-check.sh" "$tmp/log" "$2" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne "$1" ]; then
    echo "FALLA: modo=$2 changed=$3 failed=$4 unreachable=$5 -> rc=$rc, se esperaba $1" >&2
    exit 1
  fi
}

expect 0 ok 2 0 0
expect 0 ok 0 0 0
expect 1 ok 0 1 0
expect 1 ok 0 0 1
expect 0 changed 2 0 0
expect 1 changed 0 0 0
expect 0 nochange 0 0 0
expect 1 nochange 1 0 0
expect 2 bogus 0 0 0

echo "recap-check-selftest: ok (9 casos)"
