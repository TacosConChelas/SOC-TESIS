#!/usr/bin/env bash
# Deja a `honeyserver` como una VM nueva frente al agente de Wazuh: sin paquete,
# sin /var/ossec y sin registrar en el Manager. Asi el check 7 de honeypot-check
# prueba el enrolamiento del rol honeypot y no la clave que dejo el fixture de
# `wazuh-rehearse` (spec 2026-11-04-honeypot-role-design.md, D4).
set -euo pipefail

ctr=soc-local-honeyserver
mgr=soc-local-wazuh

die() { echo "honeypot-reset-agent: $*" >&2; exit 1; }

docker inspect "$ctr" >/dev/null 2>&1 || die "no existe el contenedor $ctr (corre make up)"
docker inspect "$mgr" >/dev/null 2>&1 || die "no existe el contenedor $mgr (corre make up)"

# Purgar el agente despues de `start` dejaria el senuelo sin telemetria, y el rol
# ya no vuelve a dormir el agente tras honeypot-started: mejor negarse.
if docker exec "$ctr" test -e /etc/soc-tesis/honeypot-started; then
  die "honeyserver ya arranco el senuelo (/etc/soc-tesis/honeypot-started): corre make clean preflight y make wazuh-rehearse antes de honeypot-rehearse"
fi

list="$(docker exec "$mgr" /var/ossec/bin/agent_control -l 2>/dev/null)" \
  || die "no se pudo listar los agentes del Manager en $mgr"
agent_id="$(sed -n 's/^ *ID: \([0-9][0-9]*\), Name: honeyserver,.*/\1/p' <<<"$list" | head -n1)"

installed=0
if docker exec "$ctr" dpkg -s wazuh-agent >/dev/null 2>&1; then
  installed=1
fi

if [ "$installed" -eq 0 ] && [ -z "$agent_id" ]; then
  echo "honeypot-reset-agent: el agente ya estaba ausente y sin registrar"
  exit 0
fi

if [ "$installed" -eq 1 ]; then
  if docker exec "$ctr" systemctl cat wazuh-agent >/dev/null 2>&1; then
    docker exec "$ctr" systemctl disable --now wazuh-agent
  fi
  # El rol lo deja en hold (dpkg_selections): sin este flag apt-get -y sale 100.
  docker exec "$ctr" apt-get purge -y --allow-change-held-packages wazuh-agent
  docker exec "$ctr" rm -rf /var/ossec
  # El repo lo vuelve a dejar el tag install del rol.
  docker exec "$ctr" rm -f /etc/apt/sources.list.d/wazuh.list /usr/share/keyrings/wazuh.asc
fi

if [ -n "$agent_id" ]; then
  docker exec -i "$mgr" /var/ossec/bin/manage_agents -r "$agent_id" < /dev/null
fi

rc=0
if docker exec "$ctr" dpkg -s wazuh-agent >/dev/null 2>&1; then
  echo "FALLA: wazuh-agent sigue instalado en $ctr" >&2
  rc=1
fi
if docker exec "$ctr" test -e /var/ossec; then
  echo "FALLA: /var/ossec sigue existiendo en $ctr" >&2
  rc=1
fi
if docker exec "$mgr" /var/ossec/bin/agent_control -l 2>/dev/null | grep -q 'Name: honeyserver,'; then
  echo "FALLA: $mgr sigue listando honeyserver en agent_control -l" >&2
  rc=1
fi
[ "$rc" -eq 0 ] || exit 1

echo "honeypot-reset-agent: ok (agente ausente y sin registrar)"
