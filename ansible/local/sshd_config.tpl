# Plantilla de sshd para el laboratorio local. `__PORT__` lo sustituye el
# entrypoint con SSHD_PORT (22 salvo honeyserver, que usa 22222).
# Igual que Ubuntu 22.04: los drop-ins de sshd_config.d van primero y "el primer
# valor gana". El endurecimiento (PermitRootLogin, PasswordAuthentication,
# KbdInteractiveAuthentication, MaxAuthTries) lo aporta el rol `common`; si
# estuviera aqui, los checks de common-check pasarian aunque el rol no hiciera nada.
Include /etc/ssh/sshd_config.d/*.conf

Port __PORT__
AddressFamily any
ListenAddress 0.0.0.0

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
UsePAM yes

X11Forwarding no
PrintMotd no
AcceptEnv LANG LC_*

Subsystem sftp /usr/lib/openssh/sftp-server
