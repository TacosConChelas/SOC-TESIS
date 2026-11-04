#!/usr/bin/env bash
# Verifica el rol wazuh en el ensayo local (spec 2026-10-30-wazuh-role-design.md §6).
# Requiere el all-in-one instalado (make wazuh-rehearse). Subconjunto: WAZUH_CHECKS="1 2".
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ansible_dir="$(cd "$here/../.." && pwd)"
repo="$(cd "$ansible_dir/.." && pwd)"
defaults="$ansible_dir/roles/wazuh/defaults/main.yml"
secrets="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
ctr=soc-local-wazuh
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }
wz() { docker exec "$ctr" "$@"; }
default_of() {
  sed -n -e "s/^$1:[[:space:]]*\"\([^\"]*\)\".*/\1/p" \
         -e "s/^$1:[[:space:]]*\([0-9][0-9a-z]*\)[[:space:]]*\(#.*\)\{0,1\}$/\1/p" "$defaults" | head -n1
}
admin_pass() {
  tar -axf "$secrets/wazuh-install-files.tar" wazuh-install-files/wazuh-passwords.txt -O 2>/dev/null \
    | grep -P "\'admin\'" -A 1 | tail -n 1 | sed -E "s/.*'([^']*)'.*/\1/"
}

want_version="$(default_of wazuh_expected_version)"
[ -n "$want_version" ] || { echo "FALLA: wazuh_expected_version no esta en $defaults" >&2; exit 1; }

# 1. Version esperada y paquetes retenidos.
c1() {
  local info holds pkg
  info="$(wz /var/ossec/bin/wazuh-control info 2>/dev/null || true)"
  if grep -q "WAZUH_VERSION=\"v${want_version}\"" <<<"$info"; then good "wazuh-control info reporta v${want_version}"; else bad "wazuh-control info no reporta v${want_version}"; fi
  holds="$(wz apt-mark showhold 2>/dev/null || true)"
  for pkg in wazuh-manager wazuh-indexer wazuh-dashboard filebeat; do
    if grep -qx "$pkg" <<<"$holds"; then good "$pkg retenido"; else bad "$pkg no esta retenido"; fi
  done
}

# 2. Servicios activos.
c2() {
  local svc
  for svc in wazuh-indexer wazuh-manager filebeat wazuh-dashboard; do
    if wz systemctl is-active --quiet "$svc"; then good "$svc activo"; else bad "$svc no esta activo"; fi
  done
}

# 3. Puertos de D5.
# Un JVM dual-stack liga 127.0.0.1 en un socket IPv6 y ss lo muestra como
# [::ffff:127.0.0.1]; eso es loopback igual que 127.* y [::1].
c3() {
  local tcp p
  tcp="$(wz ss -ltnH 2>/dev/null | awk '{n=split($4,a,":"); port=a[n]; addr=substr($4,1,length($4)-length(port)-1); print addr, port}')"
  for p in 1514 1515 443; do
    if awk -v p="$p" '$2==p && $1!~/^(127\.|\[::1\]|\[::ffff:127\.)/ {f=1} END{exit !f}' <<<"$tcp"; then good "puerto $p escucha en interfaces no loopback"; else bad "puerto $p no escucha fuera de loopback"; fi
  done
  for p in 9200 55000; do
    if awk -v p="$p" '$2==p {seen=1; if ($1!~/^(127\.|\[::1\]|\[::ffff:127\.)/) mal=1} END{exit !(seen && !mal)}' <<<"$tcp"; then good "puerto $p solo en loopback"; else bad "puerto $p no esta solo en loopback"; fi
  done
  for p in 9300 1516 514; do
    if awk -v p="$p" '$2==p && $1!~/^(127\.|\[::1\]|\[::ffff:127\.)/ {f=1} END{exit f}' <<<"$tcp"; then good "puerto $p sin escucha fuera de loopback"; else bad "puerto $p escucha fuera de loopback"; fi
  done
  if wz ss -lunH 2>/dev/null | awk '$4 ~ /:1514$/ {f=1} END{exit f}'; then good "1514/udp cerrado"; else bad "1514/udp escucha"; fi
}

# 4. ossec.conf.
c4() {
  local out
  if out="$(docker exec -i "$ctr" python3 - /var/ossec/etc/ossec.conf <"$here/wazuh-conf-check.py" 2>&1)"; then
    good "ossec.conf con los valores de D5"; printf '%s\n' "$out" | sed 's/^/    /'
  else
    bad "ossec.conf no cumple D5"; printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
  if wz /var/ossec/bin/wazuh-analysisd -t >/dev/null 2>&1; then good "wazuh-analysisd -t"; else bad "wazuh-analysisd -t falla"; fi
}

# 5. authd.pass.
c5() {
  local meta have want
  meta="$(wz stat -c '%a %U:%G' /var/ossec/etc/authd.pass 2>/dev/null || true)"
  if [ "$meta" = "640 root:wazuh" ]; then good "authd.pass 640 root:wazuh"; else bad "authd.pass con permisos '$meta'"; fi
  have="$(wz sha256sum /var/ossec/etc/authd.pass 2>/dev/null | cut -d' ' -f1 || true)"
  want="$(sha256sum "$secrets/authd.pass" 2>/dev/null | cut -d' ' -f1 || true)"
  if [ -n "$have" ] && [ "$have" = "$want" ]; then good "authd.pass coincide con el del controlador"; else bad "authd.pass distinto del del controlador"; fi
}

# 6. Heap del Indexer.
c6() {
  local heap
  heap="$(cd "$ansible_dir" && ansible-inventory --host wazuh 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("wazuh_indexer_heap",""))' 2>/dev/null || true)"
  [ -n "$heap" ] || heap="$(default_of wazuh_indexer_heap)"
  if wz grep -qxe "-Xms${heap}" /etc/wazuh-indexer/jvm.options && wz grep -qxe "-Xmx${heap}" /etc/wazuh-indexer/jvm.options; then
    good "jvm.options con -Xms${heap} -Xmx${heap}"
  else
    bad "jvm.options sin -Xms${heap} / -Xmx${heap}"
  fi
}

# 7. Politica ISM de retencion.
c7() {
  local days pw resp
  days="$(default_of wazuh_retention_days)"
  pw="$(admin_pass || true)"
  if [ -z "$pw" ]; then bad "no se pudo leer la contrasena de admin de $secrets/wazuh-install-files.tar"; return; fi
  resp="$(printf 'user = "admin:%s"\n' "$pw" \
    | docker exec -i "$ctr" curl -sk -K - "https://127.0.0.1:9200/_plugins/_ism/policies/wazuh-alert-retention-policy" || true)"
  if python3 - "$resp" "$days" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
pol = d["policy"]
pol = pol.get("policy", pol)
edades = [t["conditions"]["min_index_age"] for s in pol["states"] for t in s.get("transitions", []) if "conditions" in t]
pats = [p for t in (pol.get("ism_template") or []) for p in t.get("index_patterns", [])]
sys.exit(0 if f"{sys.argv[2]}d" in edades and "wazuh-alerts-*" in pats else 1)
PY
  then good "politica ISM borra wazuh-alerts-* a ${days}d"; else bad "la politica ISM no existe o no borra wazuh-alerts-* a ${days}d"; fi
}

# 8. Higiene de secretos.
c8() {
  if wz test ! -e /root/wazuh-install-files.tar; then good "el tar no queda en la VM"; else bad "el tar sigue en la VM"; fi
  if wz test ! -e /var/log/wazuh-install.log; then good "el log del asistente no queda en la VM"; else bad "el log del asistente sigue en la VM"; fi
  if [ "$(stat -c %a "$secrets/wazuh-install-files.tar" 2>/dev/null || true)" = 600 ]; then good "tar en el controlador con 0600"; else bad "falta el tar en $secrets o no es 0600"; fi
  if (cd "$repo" && python3 ansible/local/scripts/secret-scan.py >/dev/null 2>&1); then good "secret-scan limpio"; else bad "secret-scan encontro secretos"; fi
}

# 9. Cadena D4 real: agente en honeyserver enrolado por el relay.
c9() {
  local _
  for _ in $(seq 1 12); do
    if wz /var/ossec/bin/agent_control -l 2>/dev/null | grep -Eq 'Name: honeyserver, IP: any, Active'; then
      good "agente honeyserver activo en el Manager (enrolado por el relay)"; return
    fi
    sleep 5
  done
  bad "el agente honeyserver no aparece activo en agent_control -l"
}

# 10. Prueba negativa del gate de version.
c10() {
  local out
  if [ -z "${ANSIBLE_INVENTORY:-}" ]; then bad "ejecuta este check via make wazuh-check (faltan las variables ANSIBLE_*)"; return; fi
  out="$(cd "$ansible_dir" && ansible-playbook site.yml --limit wazuh --tags install \
    -e wazuh_enabled=true -e wazuh_expected_version=4.14.0 2>&1 || true)"
  if grep -q 'desviación del baseline D1' <<<"$out"; then good "el gate de version falla con una version distinta"; else bad "el gate de version no fallo con wazuh_expected_version=4.14.0"; fi
}

for n in ${WAZUH_CHECKS:-1 2 3 4 5 6 7 8 9 10}; do "c$n"; done

if [ "$fail" -ne 0 ]; then
  echo "wazuh-check: FALLA" >&2
  exit 1
fi
echo "wazuh-check: ok"
