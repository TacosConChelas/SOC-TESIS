#!/usr/bin/env bash
# Prepara sshd dentro del contenedor y arranca systemd como PID 1.
set -euo pipefail

port="${SSHD_PORT:-22}"

sed "s/__PORT__/${port}/g" /etc/ssh/sshd_config.soc > /etc/ssh/sshd_config
chmod 0644 /etc/ssh/sshd_config
mkdir -p /run/sshd

# Claves de host nuevas en cada recreación: simula el known_hosts desechable
# de la Etapa 4a (las huellas reales se obtienen por run-command).
ssh-keygen -A >/dev/null

# Llave desechable generada por scripts/gen-local-keys.sh y montada en /keys.
if [ -f /keys/local_ed25519.pub ]; then
  install -d -m 0700 -o soctesis -g soctesis /home/soctesis/.ssh
  install -m 0600 -o soctesis -g soctesis \
    /keys/local_ed25519.pub /home/soctesis/.ssh/authorized_keys
fi

mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sf /lib/systemd/system/ssh.service \
  /etc/systemd/system/multi-user.target.wants/ssh.service
# Sin esta unidad queda /run/nologin y sshd rechaza a los usuarios no root
# ("System is booting up..."). El target la arranca y retira /run/nologin.
ln -sf /lib/systemd/system/systemd-user-sessions.service \
  /etc/systemd/system/multi-user.target.wants/systemd-user-sessions.service

exec "$@"
