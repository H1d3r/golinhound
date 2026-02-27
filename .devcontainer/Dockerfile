FROM mcr.microsoft.com/devcontainers/go:latest

RUN useradd -m -s /bin/bash alice
RUN useradd -m -s /bin/bash alice_adm

RUN usermod -aG sudo alice_adm

RUN su - alice -c "ssh-keygen -t ed25519 -m RFC4716 -f ~/.ssh/id_ed25519_RFC4716_passwd   -N 'password'"
RUN su - alice -c "ssh-keygen -t ed25519 -m RFC4716 -f ~/.ssh/id_ed25519_RFC4716_nopasswd -N ''"
RUN su - alice -c "ssh-keygen -t ecdsa   -m PKCS8   -f ~/.ssh/id_ecdsa_PKCS8_passwd       -N 'password'"
RUN su - alice -c "ssh-keygen -t ecdsa   -m PKCS8   -f ~/.ssh/id_ecdsa_PKCS8_nopasswd     -N ''"
RUN su - alice -c "ssh-keygen -t rsa     -m PEM     -f ~/.ssh/id_rsa_PEM_passwd           -N 'password'"
RUN su - alice -c "ssh-keygen -t rsa     -m PEM     -f ~/.ssh/id_rsa_PEM_nopasswd         -N ''"

RUN cat /home/alice/.ssh/id_*.pub > /home/alice/.ssh/authorized_keys
RUN chown alice:alice /home/alice/.ssh/authorized_keys
RUN chmod 600 /home/alice/.ssh/authorized_keys

RUN su - alice_adm -c "mkdir /home/alice_adm/.ssh/"
RUN cat /home/alice/.ssh/id_*.pub > /home/alice_adm/.ssh/authorized_keys
RUN chown alice_adm:alice_adm /home/alice_adm/.ssh/authorized_keys
RUN chmod 600 /home/alice_adm/.ssh/authorized_keys

RUN apt update && apt install openssh-server krb5-user screen -y

RUN ktutil <<EOF
addent -password -p svc_custom@DEMO.LOCAL -k 1 -e aes256-cts-hmac-sha1-96
H2dPxOY3jBy6NPNoyAeUhVaUSH
wkt /home/alice/svc_custom.keytab
EOF

RUN ktutil <<EOF
addent -password -p host/server.demo.local@DEMO.LOCAL -k 1 -e aes256-cts-hmac-sha1-96
ZEPf5afMvQzwDR9wgsoXiO2OXE
wkt /etc/krb5.keytab
EOF