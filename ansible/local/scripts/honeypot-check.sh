#!/usr/bin/env bash
# Verifica el rol honeypot en el ensayo local (spec 2026-11-04-honeypot-role-design.md §6).
# Requiere make honeypot-rehearse (y antes make wazuh-rehearse). Subconjunto: HONEYPOT_CHECKS="1 2".
# El check 3 (todo dormido tras install,config) no va en la lista por defecto: lo llama
# honeypot-rehearse justo despues de la 1a pasada.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ansible_dir="$(cd "$here/../.." && pwd)"
repo="$(cd "$ansible_dir/.." && pwd)"
defaults="$ansible_dir/roles/honeypot/defaults/main.yml"
shared="$ansible_dir/group_vars/all.yml"
secrets="${WAZUH_LOCAL_SECRETS_DIR:-/tmp/soc-local-secrets}"
ctr=soc-local-honeyserver
mgr=soc-local-wazuh
attacker=soc-local-logrelay
hp_ip=10.50.10.10
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }
hs() { docker exec "$ctr" "$@"; }
var_of() { sed -n "s/^$2:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$1" 2>/dev/null | head -n1 || true; }
banner() { docker exec "$attacker" timeout 5 bash -c "exec 3<>/dev/tcp/$1/$2; head -n1 <&3" 2>/dev/null | tr -d '\r' || true; }

docker_version="$(var_of "$defaults" honeypot_docker_version)"
containerd_version="$(var_of "$defaults" honeypot_containerd_version)"
compose_version="$(var_of "$defaults" honeypot_compose_version)"
agent_version="$(var_of "$shared" wazuh_expected_version)-1"
mapfile -t images < <(sed -n 's/^[A-Z_]*_IMAGE=//p' "$repo/.env.example")

# 1. Paquetes en la version fijada, retenidos, y sin recomendados.
c1() {
  local holds row pkg want have
  holds="$(hs apt-mark showhold 2>/dev/null || true)"
  for row in "docker-ce $docker_version" "docker-ce-cli $docker_version" "containerd.io $containerd_version" \
             "docker-compose-plugin $compose_version" "wazuh-agent $agent_version"; do
    read -r pkg want <<<"$row"
    have="$(hs dpkg-query -W -f "\${Version}" "$pkg" 2>/dev/null || true)"
    if [ -n "$want" ] && [ "$have" = "$want" ]; then good "$pkg $want"; else bad "$pkg en '$have', se esperaba '$want'"; fi
    if grep -qxF "$pkg" <<<"$holds"; then good "$pkg retenido"; else bad "$pkg no esta retenido"; fi
  done
  for pkg in docker-buildx-plugin docker-ce-rootless-extras; do
    if hs dpkg -s "$pkg" >/dev/null 2>&1; then bad "$pkg instalado (debia quedar fuera)"; else good "$pkg ausente"; fi
  done
}

# 2. RepoDigests iguales a .env.example (requiere el daemon arriba: tras start).
c2() {
  local ref pinned have
  [ "${#images[@]}" -eq 7 ] || bad ".env.example tiene ${#images[@]} imagenes, se esperaban 7"
  for ref in "${images[@]}"; do
    pinned="$(sed -E 's#:[^/@]+@#@#' <<<"$ref")"
    have="$(hs docker image inspect --format '{{join .RepoDigests " "}}' "$pinned" 2>/dev/null || true)"
    if tr ' ' '\n' <<<"$have" | grep -qxF "$pinned"; then good "digest $pinned"; else bad "imagen $pinned ausente o con otro digest ('$have')"; fi
  done
}

# 3. E1-3: tras install,config nada del senuelo activo ni habilitado.
c3() {
  local u
  for u in docker.service docker.socket containerd.service wazuh-agent.service; do
    if hs systemctl is-active --quiet "$u"; then bad "$u activo con el egreso abierto"; else good "$u inactivo"; fi
    if hs systemctl is-enabled --quiet "$u" 2>/dev/null; then bad "$u habilitado con el egreso abierto"; else good "$u deshabilitado"; fi
  done
  if hs test -e /etc/soc-tesis/honeypot-started; then bad "honeypot-started existe antes de start"; else good "sin honeypot-started"; fi
  if hs test -s /etc/soc-tesis/honeypot-images; then good "centinela de imagenes escrito"; else bad "falta /etc/soc-tesis/honeypot-images"; fi
}

# 4. Tras start: 7 contenedores sanos; el 22 lo atiende Cowrie; sshd del host en el 22222.
c4() {
  local n s22 s22222 eff
  n="$(hs docker ps --filter 'name=^soc-tesis-' --filter health=healthy --format '{{.Names}}' 2>/dev/null | grep -c '^soc-tesis-' || true)"
  if [ "$n" -eq 7 ]; then good "7 contenedores healthy"; else bad "$n contenedores healthy, se esperaban 7"; fi
  s22="$(banner "$hp_ip" 22)"
  s22222="$(banner "$hp_ip" 22222)"
  if [ -n "$s22" ] && [ -n "$s22222" ] && [ "$s22" != "$s22222" ]; then
    good "el 22 lo atiende el senuelo ('$s22'), no el sshd del host ('$s22222')"
  else
    bad "banners del 22 ('$s22') y del 22222 ('$s22222'): el senuelo no atiende el 22"
  fi
  eff="$(hs /usr/sbin/sshd -T 2>/dev/null | grep '^port ' || true)"
  if [ "$eff" = "port 22222" ]; then good "sshd del host solo en 22222"; else bad "sshd -T: '$eff'"; fi
}

# 5. ossec.conf del agente (D4).
c5() {
  local out
  if out="$(docker exec -i "$ctr" python3 - /var/ossec/etc/ossec.conf <"$here/honeypot-conf-check.py" 2>&1)"; then
    good "ossec.conf: $out"
  else
    bad "ossec.conf no cumple D4"; printf '%s\n' "$out" | sed 's/^/    /' >&2
  fi
}

# 6. authd.pass.
c6() {
  local meta have want
  meta="$(hs stat -c '%a %U:%G' /var/ossec/etc/authd.pass 2>/dev/null || true)"
  if [ "$meta" = "640 root:wazuh" ]; then good "authd.pass 640 root:wazuh"; else bad "authd.pass con permisos '$meta'"; fi
  have="$(hs sha256sum /var/ossec/etc/authd.pass 2>/dev/null | cut -d' ' -f1 || true)"
  want="$(sha256sum "$secrets/authd.pass" 2>/dev/null | cut -d' ' -f1 || true)"
  if [ -n "$have" ] && [ "$have" = "$want" ]; then good "authd.pass coincide con el del controlador"; else bad "authd.pass distinto del del controlador"; fi
}

# 7. El agente del honeyserver aparece activo en el Manager (a traves del relay).
c7() {
  local _
  for _ in $(seq 1 12); do
    if docker exec "$mgr" /var/ossec/bin/agent_control -l 2>/dev/null | grep -Eq 'Name: honeyserver, IP: any, Active'; then
      good "agente honeyserver activo en el Manager"; return
    fi
    sleep 5
  done
  bad "el agente honeyserver no aparece activo en agent_control -l"
}

# 8. Cada honeypot escribe su evento y wazuh-logcollector lo lee (D4).
c8() {
  local t0 f _ ok state
  t0="$(hs date +%s)"
  sleep 1
  docker exec "$attacker" timeout 10 bash -c "exec 3<>/dev/tcp/$hp_ip/22; printf 'SSH-2.0-soc-probe\r\n' >&3; sleep 3" || true
  docker exec "$attacker" timeout 10 bash -c "exec 3<>/dev/tcp/$hp_ip/21; printf 'USER soc-probe\r\n' >&3; sleep 3" || true
  docker exec "$attacker" curl -s -m 10 -o /dev/null "http://$hp_ip/soc-probe" || true
  docker exec "$attacker" timeout 10 bash -c "exec 3<>/dev/tcp/$hp_ip/25; printf 'HELO soc-probe\r\nQUIT\r\n' >&3; sleep 3" || true

  for f in cowrie/log/cowrie.json dionaea/lib/dionaea.json tanner/log/tanner_report.json; do
    ok=0
    for _ in $(seq 1 18); do
      if [ "$(hs stat -c %Y "/srv/soc-tesis/$f" 2>/dev/null || echo 0)" -ge "$t0" ]; then ok=1; break; fi
      sleep 10
    done
    if [ "$ok" -eq 1 ]; then good "$f recibio el evento de prueba"; else bad "$f no cambio tras el evento de prueba"; fi
  done
  if [ "$(hs journalctl CONTAINER_NAME=soc-tesis-mailoney --since "@$t0" -o cat --no-pager 2>/dev/null | grep -c . || true)" -gt 0 ]; then
    good "Mailoney escribio en journald"
  else
    bad "Mailoney no escribio en journald tras el evento de prueba"
  fi

  ok=0
  for _ in $(seq 1 9); do
    state="$(hs cat /var/ossec/var/run/wazuh-logcollector.state 2>/dev/null || true)"
    if [ -n "$state" ] && python3 - "$state" <<'PY'
import json, sys
seen = {}
def walk(x):
    if isinstance(x, dict):
        if "location" in x and "events" in x:
            seen[x["location"]] = max(seen.get(x["location"], 0), int(x["events"]))
        for v in x.values():
            walk(v)
    elif isinstance(x, list):
        for v in x:
            walk(v)
walk(json.loads(sys.argv[1]))
want = ["/srv/soc-tesis/cowrie/log/cowrie.json", "/srv/soc-tesis/dionaea/lib/dionaea.json",
        "/srv/soc-tesis/tanner/log/tanner_report.json", "journald"]
sys.exit(0 if all(seen.get(w, 0) > 0 for w in want) else 1)
PY
    then ok=1; break; fi
    sleep 10
  done
  if [ "$ok" -eq 1 ]; then good "wazuh-logcollector leyo eventos de los 4 localfile"; else bad "wazuh-logcollector.state sin eventos en los 4 localfile ('${state:0:300}')"; fi
}

# 9. Prueba negativa: con el egreso abierto, start falla en la sonda.
c9() {
  local out
  if [ -z "${ANSIBLE_INVENTORY:-}" ]; then bad "ejecuta este check via make honeypot-check (faltan las variables ANSIBLE_*)"; return; fi
  bash "$here/net-toggle.sh" install >/dev/null
  out="$(cd "$ansible_dir" && ansible-playbook site.yml --limit honeyserver --tags start -e honeypot_enabled=true 2>&1 || true)"
  bash "$here/net-toggle.sh" operate >/dev/null
  if grep -q 'el egreso sigue abierto' <<<"$out"; then good "start se niega a arrancar con el egreso abierto"; else bad "start no fallo en la sonda de egreso con el egreso abierto"; fi
}

# 10. Reinicio: un contenedor ya creado debe volver healthy al arrancar de nuevo (tmpfs de tanner;
# restart: unless-stopped tras deallocate/start). Sin mode=1777 el 2o arranque fallaba.
c10() {
  local n h
  for n in 1 2; do
    hs docker restart soc-tesis-tanner >/dev/null
    h=""
    for _ in $(seq 1 18); do
      h="$(hs docker inspect --format '{{.State.Health.Status}}' soc-tesis-tanner 2>/dev/null || true)"
      [ "$h" = healthy ] && break
      sleep 10
    done
    if [ "$h" = healthy ]; then good "tanner healthy tras el reinicio $n"; else bad "tanner '$h' tras el reinicio $n"; fi
  done
}

for n in ${HONEYPOT_CHECKS:-1 2 4 5 6 7 8 9 10}; do "c$n"; done

if [ "$fail" -ne 0 ]; then
  echo "honeypot-check: FALLA" >&2
  exit 1
fi
echo "honeypot-check: ok"
