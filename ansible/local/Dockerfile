# Simula una VM Ubuntu 22.04 de Azure para el ensayo local de Ansible.
# Necesita systemd como PID 1 y sshd; la imagen base no trae openssh-server.
FROM jrei/systemd-ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      iproute2 \
      iputils-ping \
      openssh-server \
      python3 \
      sudo \
 && rm -rf /var/lib/apt/lists/* \
 && rm -f /etc/ssh/ssh_host_* \
 && mkdir -p /run/sshd

RUN useradd --create-home --shell /bin/bash soctesis \
 && printf 'soctesis ALL=(ALL) NOPASSWD:ALL\n' > /etc/sudoers.d/90-soctesis \
 && chmod 0440 /etc/sudoers.d/90-soctesis

COPY sshd_config.tpl /etc/ssh/sshd_config.soc
COPY entrypoint.sh /usr/local/bin/soc-entrypoint
RUN chmod 0755 /usr/local/bin/soc-entrypoint

EXPOSE 22 22222

ENTRYPOINT ["/usr/local/bin/soc-entrypoint"]
CMD ["/sbin/init"]
