#!/bin/bash
# Bootstrap de la VM strongSwan respondedora (ADR-006 E1-1/E1-5).
# Lo ejecuta managed run command con el parámetro protegido PSK.
# Sin set -x: este script maneja el secreto. printf es builtin (no aparece en argv).
set -eu
: "${PSK:?falta el parámetro protegido PSK}"
LOCAL_ID=azure-vpn.soc-tesis   # P3
PEER_ID=pi.soc-tesis           # P3
LOCAL_TS=10.50.0.0/16          # P4
REMOTE_TS=192.168.1.0/24       # P4

export DEBIAN_FRONTEND=noninteractive
# charon-systemd es el daemon IKE (strongswan.service); swanctl solo es la CLI.
if [ "$(dpkg-query -W -f='${db:Status-Abbrev}\n' strongswan-swanctl charon-systemd 2>/dev/null | grep -c '^ii')" != 2 ]; then
  apt-get update -q
  apt-get install -y -q strongswan-swanctl charon-systemd
fi

# Mismo contenido que escribe el rol strongswan: su primera pasada no cambia nada.
printf '%s\n' '# ADR-006 E1-1: la VM strongSwan reenvía solo lo que entra por el túnel.' \
  'net.ipv4.ip_forward = 1' >/etc/sysctl.d/99-soc-strongswan.conf
sysctl -p /etc/sysctl.d/99-soc-strongswan.conf

install -m 0644 -o root -g root /dev/null /etc/swanctl/conf.d/10-lab.conf
cat >/etc/swanctl/conf.d/10-lab.conf <<EOF
connections {
  lab {
    version = 2
    local_addrs = 10.50.20.10
    remote_addrs = %any
    proposals = aes256gcm16-prfsha384-ecp384
    dpd_delay = 30s
    local { auth = psk
            id = $LOCAL_ID }
    remote { auth = psk
             id = $PEER_ID }
    children {
      lab {
        local_ts = $LOCAL_TS
        remote_ts = $REMOTE_TS
        esp_proposals = aes256gcm16-ecp384
        dpd_action = clear
      }
    }
  }
}
EOF

install -m 0600 -o root -g root /dev/null /etc/swanctl/conf.d/90-lab-secret.conf
printf 'secrets {\n  ike-lab {\n    id = %s\n    secret = 0x%s\n  }\n}\n' "$PEER_ID" "$PSK" \
  >/etc/swanctl/conf.d/90-lab-secret.conf

systemctl enable --now strongswan
swanctl --load-all >/dev/null
swanctl --list-conns
printf 'psk-sha256: %s\n' "$(printf '%s' "$PSK" | sha256sum | cut -c1-12)"
