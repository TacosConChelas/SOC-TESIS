#!/usr/bin/env bash
# Escaneo de secretos con git grep (archivos rastreados y no ignorados). Sin exclusiones.
# Uso: secret-scan.sh [dir]     (por defecto el repo)   |   secret-scan.sh --selftest
set -uo pipefail

pem='-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----'
# asignacion literal de PSK/secret; ignora referencias ($VAR, {{ var }}, <...>, %...)
lit="(psk|pre[_-]?shared[_-]?key|secret)[[:space:]]*[:=][[:space:]]*[\"']?[^[:space:]\"'#\$<{%!]{8,}"
# nombre de credencial = 64 hex (llave/clave en claro); no toca digests sha256 sueltos
hex="(psk|secret|pass|token|key)[a-z0-9_-]*[[:space:]]*[:=][[:space:]]*[\"']?[0-9a-f]{64}"

scan() { # $1=dir -> 0 limpio, 1 hallazgo, 2 error
  cd "$1" || return 2
  local rc found=0 re msg
  for re in "$pem" "$lit" "$hex"; do
    case "$re" in "$pem") msg="llave privada PEM";; "$lit") msg="PSK o secret literal";; *) msg="credencial de 64 hex";; esac
    git grep -I -n -i -E --untracked -e "$re" -- . | cut -d: -f1,2 | sed "s|^|secret-scan: $msg en |" >&2
    rc=${PIPESTATUS[0]}
    case "$rc" in 0) found=1;; 1) ;; *) echo "secret-scan: error de git grep ($rc)" >&2; return 2;; esac
  done
  return "$found"
}

selftest() {
  local d rc; d="$(mktemp -d)"; trap 'rm -rf "$d"' RETURN
  git -C "$d" init -q
  scan "$d" 2>/dev/null || { echo "selftest: repo vacio debe pasar" >&2; return 1; }
  printf 'ipsec_psk: "%s"\n' "xK9fQ2mZpL7vB3nT" >"$d/a.yml"
  printf 'authd_key=%s\n' "$(printf 'ab%.0s' {1..32})" >"$d/b.env"
  printf -- '-----BEGIN %s PRIVATE KEY-----\n' RSA >"$d/c.pem"
  printf 'psk: "{{ lookup(env) }}"\nimage: x@sha256:%s\n' "$(printf 'cd%.0s' {1..32})" >"$d/ok.yml"
  rm "$d/a.yml"; scan "$d" 2>/dev/null; [ $? -eq 1 ] || { echo "selftest: no detecto hex64 / PEM" >&2; return 1; }
  rm "$d/b.env" "$d/c.pem"; scan "$d" 2>/dev/null || { echo "selftest: falso positivo en referencias o digests" >&2; return 1; }
  printf 'ipsec_psk: "%s"\n' "xK9fQ2mZpL7vB3nT" >"$d/a.yml"; scan "$d" 2>/dev/null; [ $? -eq 1 ] || { echo "selftest: no detecto PSK literal" >&2; return 1; }
  echo "secret-scan selftest: ok"
}

if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi
scan "${1:-$(git -C "$(dirname "$0")" rev-parse --show-toplevel)}"; rc=$?
[ "$rc" -eq 0 ] && echo "secret-scan: ok"
exit "$rc"
