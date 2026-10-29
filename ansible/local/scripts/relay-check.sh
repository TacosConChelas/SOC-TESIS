#!/usr/bin/env bash
# Verifica el rol logrelay en el ensayo local (spec 2026-10-29-logrelay-role-design.md §5).
# Requiere los contenedores arriba y convergidos (make rehearse).
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
probe="$here/relay-probe.py"
defaults="$here/../../roles/logrelay/defaults/main.yml"

relay=soc-local-logrelay
manager=soc-local-wazuh
agent=soc-local-honeyserver
other=soc-local-strongswan
relay_ip=10.50.30.10
token="relay-check-$(date +%s)-$$"
fail=0

bad() { echo "FALLA: $*" >&2; fail=1; }
good() { echo "ok: $*"; }

# Manager falso en wazuh: eco en 1514 y 1515; se apaga solo a los 90 s.
docker cp "$probe" "$manager:/tmp/relay-probe.py"
docker exec -d "$manager" python3 /tmp/relay-probe.py serve 90 1514 1515
# El corchete evita que el sh -c se mate a si mismo (su cmdline no casa con la regex).
cleanup() {
  docker exec "$manager" sh -c 'for p in /proc/[0-9]*; do grep -qa "relay-probe[.]py" "$p/cmdline" 2>/dev/null && kill "${p#/proc/}" 2>/dev/null; done; true' >/dev/null 2>&1 || true
}
trap cleanup EXIT
sleep 1

run_probe() { # contenedor puerto modo
  docker exec -i "$1" python3 - probe "$relay_ip" "$2" "$token" "$3" <"$probe"
}

# 1. Paso L4 desde el agente permitido.
for port in 1514 1515; do
  if run_probe "$agent" "$port" echo; then good "honeyserver -> relay:$port pasa al Manager"; else bad "honeyserver no llega al Manager por el relay:$port"; fi
done

# 2. Origen no permitido: sin eco.
for port in 1514 1515; do
  if run_probe "$other" "$port" none; then good "strongswan -> relay:$port bloqueado"; else bad "strongswan recibio eco por relay:$port (deny all no actua)"; fi
done

# 3. access_log: metadatos si, contenido no.
sleep 1
log="$(docker exec "$relay" cat /var/log/soc-relay/stream.log 2>/dev/null || true)"
if grep -Eq '^10\.50\.10\.10 \[[^]]+\] TCP 200 ' <<<"$log"; then good "log registra la sesion permitida (200)"; else bad "el log no registra la sesion 200 de 10.50.10.10"; fi
if grep -Eq '^10\.50\.20\.10 \[[^]]+\] TCP 403 ' <<<"$log"; then good "log registra la sesion denegada (403)"; else bad "el log no registra la sesion 403 de 10.50.20.10"; fi
if grep -q "$token" <<<"$log"; then bad "el log contiene el contenido de la sesion"; else good "el log no contiene el contenido"; fi

# 4. Config valida, versión fijada y paquetes retenidos.
want="$(sed -n 's/^logrelay_nginx_version: *"\([^"]*\)".*/\1/p' "$defaults" 2>/dev/null || true)"
have="$(docker exec "$relay" dpkg-query -W -f='${Version}' nginx 2>/dev/null || true)"
if [ -n "$want" ] && [ "$want" = "$have" ]; then good "nginx $have (fijada)"; else bad "version de nginx '$have', se esperaba '$want'"; fi
if docker exec "$relay" nginx -t >/dev/null 2>&1; then good "nginx -t"; else bad "nginx -t falla"; fi
if docker exec "$relay" systemctl is-active --quiet nginx; then good "nginx activo"; else bad "nginx no esta activo"; fi
holds="$(docker exec "$relay" apt-mark showhold 2>/dev/null || true)"
owner="$(docker exec "$relay" dpkg -S /usr/sbin/nginx 2>/dev/null | cut -d: -f1 || true)"
for pkg in nginx nginx-core nginx-common libnginx-mod-stream; do
  if grep -qx "$pkg" <<<"$holds"; then good "$pkg retenido"; else bad "$pkg no esta retenido"; fi
done
if [ -n "$owner" ] && grep -qx "$owner" <<<"$holds"; then good "el dueño de /usr/sbin/nginx ($owner) esta retenido"; else bad "el dueño de /usr/sbin/nginx ('$owner') no esta retenido"; fi

# 5. logrotate valido.
if docker exec "$relay" logrotate -d /etc/logrotate.d/soc-relay >/dev/null 2>&1; then good "logrotate -d"; else bad "logrotate -d falla"; fi

if [ "$fail" -ne 0 ]; then
  echo "relay-check: FALLA" >&2
  exit 1
fi
echo "relay-check: ok"
