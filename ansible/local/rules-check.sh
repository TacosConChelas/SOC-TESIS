#!/usr/bin/env bash
# Verifica las reglas locales de Wazuh (ansible/roles/wazuh/files/local_rules.xml) en el
# manager del ensayo local: copia el XML, lo valida con analysisd -t y pasa cada fixture de
# ansible/local/fixtures/rules por wazuh-logtest en UNA sola sesion (las frecuencias acumulan).
# Requiere el manager activo (make wazuh-rehearse). Uso: rules-check.sh [contenedor]
# wazuh-logtest carga el ruleset al arrancar, asi que no hace falta reiniciar analysisd.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ansible_dir="$(cd "$here/.." && pwd)"
rules_src="$ansible_dir/roles/wazuh/files/local_rules.xml"
fixtures="$here/fixtures/rules"
expected="$fixtures/expected.tsv"
ctr="${1:-soc-local-wazuh}"
work="$(mktemp -d)"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
wz() { docker exec "$ctr" "$@"; }

[ -f "$rules_src" ] || { echo "FALLA: no existe $rules_src" >&2; exit 1; }
[ -f "$expected" ] || { echo "FALLA: no existe $expected" >&2; exit 1; }
wz test -x /var/ossec/bin/wazuh-logtest || { echo "FALLA: $ctr sin wazuh-logtest (corre make wazuh-rehearse antes)" >&2; exit 1; }

# 1. Copiar el XML y validarlo con el propio analysisd.
docker cp "$rules_src" "$ctr:/var/ossec/etc/rules/local_rules.xml"
wz chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
wz chmod 0660 /var/ossec/etc/rules/local_rules.xml
if wz /var/ossec/bin/wazuh-analysisd -t >"$work/analysisd-t.log" 2>&1; then
  echo "ok: wazuh-analysisd -t con local_rules.xml"
else
  bad "wazuh-analysisd -t rechaza local_rules.xml (ver $work/analysisd-t.log)"
  cat "$work/analysisd-t.log" >&2
  exit 1
fi

# 2. Un solo fichero de entrada: fixtures en orden, y su manifiesto (idx, archivo, linea).
inp="$work/input.txt"
manifest="$work/manifest.tsv"
: >"$inp"
: >"$manifest"
n=0
for f in cowrie dionaea mailoney tanner; do
  ln=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    ln=$((ln + 1))
    [[ -z "$line" ]] && continue
    n=$((n + 1))
    printf '%s\n' "$line" >>"$inp"
    printf '%s\t%s.jsonl\t%s\n' "$n" "$f" "$ln" >>"$manifest"
  done <"$fixtures/$f.jsonl"
done

# 3. Una sesion de wazuh-logtest con todas las lineas.
docker exec -i "$ctr" /var/ossec/bin/wazuh-logtest <"$inp" >"$work/logtest.out" 2>&1 \
  || bad "wazuh-logtest termino con error (salida en $work/logtest.out)"

# 4. Por evento (bloque que empieza en "**Phase 1"), los rule.id de la fase 3.
awk '
  /^\*\*Phase 1/ { ev++; ph = 1 }
  /^\*\*Phase 2/ { ph = 2 }
  /^\*\*Phase 3/ { ph = 3 }
  ph == 3 && match($0, /id: .[0-9]+./) { id = substr($0, RSTART + 5, RLENGTH - 6); ids[ev] = ids[ev] " " id }
  END { print ev + 0 > "/dev/stderr"; for (i = 1; i <= ev; i++) print i, ids[i] }
' "$work/logtest.out" >"$work/ids.txt" 2>"$work/count.txt"
got_events="$(cat "$work/count.txt")"
[ "$got_events" = "$n" ] || bad "wazuh-logtest devolvio $got_events bloques de evento para $n lineas (ver $work/logtest.out)"

# 5. Comparar con expected.tsv (lineas en blanco y las que empiezan por # se ignoran).
rows=0
while IFS=$'\t' read -r file lineno want; do
  [[ -z "${file:-}" || "$file" == \#* ]] && continue
  rows=$((rows + 1))
  idx="$(awk -F'\t' -v f="$file" -v l="$lineno" '$2 == f && $3 == l { print $1 }' "$manifest")"
  if [ -z "$idx" ]; then
    bad "$file:$lineno no existe en los fixtures"
    continue
  fi
  got="$(awk -v i="$idx" '$1 == i { $1 = ""; print }' "$work/ids.txt")"
  case "$want" in
    !*)
      rng="${want#!}"
      lo="${rng%-*}"
      hi="${rng#*-}"
      for id in $got; do
        if [ "$id" -ge "$lo" ] && [ "$id" -le "$hi" ]; then
          bad "$file:$lineno caso negativo: rule.id $id dentro de $lo-$hi (got:$got)"
        fi
      done
      ;;
    *)
      case " $got " in
        *" $want "*) ;;
        *) bad "$file:$lineno esperado $want, obtenido:${got:- (ninguno)}" ;;
      esac
      ;;
  esac
  if [ "$file" = "cowrie.jsonl" ]; then
    case " $got " in
      *" 1002 "*) bad "$file:$lineno la regla generica 1002 gana sobre las reglas de Cowrie (got:$got)" ;;
    esac
  fi
done <"$expected"

[ "$rows" = "$n" ] || bad "expected.tsv tiene $rows filas para $n lineas de fixtures"

if [ "$fail" -eq 0 ]; then
  rm -rf "$work"
  echo "rules-check: ok ($n eventos)"
else
  echo "rules-check: discrepancias (salida de logtest en $work/logtest.out)" >&2
  exit 1
fi
