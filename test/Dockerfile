FROM phusion/baseimage:focal-1.0.0
RUN apt-get update && apt-get install -y \
        sudo \
        netcat \
    && rm -rf /var/lib/apt/lists/*

RUN rm -f /etc/service/sshd/down
RUN /etc/my_init.d/00_regen_ssh_host_keys.sh

RUN useradd -G sudo -p '$1$Q.Yvz8ZY$SkUxPhYlU5fFk2SBPRGyw.' -m testuser
RUN sudo -u testuser ssh-keygen -t ed25519 -f ~testuser/.ssh/id_rsa \
 && sudo -u testuser cp ~testuser/.ssh/id_rsa.pub ~testuser/.ssh/authorized_keys \
 && sudo -u testuser bash -c 'cat /etc/ssh/ssh_host_*_key.pub |sed -e "s/^/localhost /" > ~testuser/.ssh/known_hosts'

HEALTHCHECK --timeout=1s --interval=1s \
  CMD sudo -u testuser ssh -l testuser -p 22 localhost true

EXPOSE 22
