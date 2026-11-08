#!/usr/bin/env bash
# Selftest de plan-check.py: el control debe pasar y cada caso a-f fallar por
# su propio check. No usa datos reales.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOCAL=$(dirname "$SCRIPT_DIR")
PY=${PY:-python3}
OUT="$LOCAL/.selftest"

mkdir -p "$OUT"
chmod 700 "$OUT"

for case in control a b c d e f; do
  "$PY" "$SCRIPT_DIR/plan-fixture.py" --case "$case" >"$OUT/plan-$case.json"
done

if ! "$PY" "$SCRIPT_DIR/plan-check.py" "$OUT/plan-control.json"; then
  echo "plan-check-selftest: FALLA (el control no pasa)" >&2
  exit 1
fi
echo "ok: control pasa los 6 checks"

fail=0
for case in a b c d e f; do
  log="$OUT/plan-$case.err"
  if "$PY" "$SCRIPT_DIR/plan-check.py" "$OUT/plan-$case.json" >/dev/null 2>"$log"; then
    echo "plan-check-selftest: FALLA (el caso $case paso y debia fallar)" >&2
    fail=1
    continue
  fi
  if grep -q -- "- \[$case\]" "$log"; then
    echo "ok: caso $case falla por [$case]"
  else
    echo "plan-check-selftest: FALLA (el caso $case no nombra su check)" >&2
    sed 's/^/    /' "$log" >&2
    fail=1
  fi
done

[ "$fail" -eq 0 ] || exit 1
echo "plan-check-selftest: ok (control + 6 casos)"
