#!/usr/bin/env bash

# A script to install docker-compose in Linux
#  https://docs.docker.com/install/linux/docker-ce/ubuntu/
#  https://docs.docker.com/compose/install/#install-compose
set -x
set -e

APT_OPTIONS='-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confnew'
DOCKER_COMPOSE_BIN='/usr/local/bin/docker-compose'

export LC_ALL="en_US.UTF-8"
export DEBIAN_FRONTEND="noninteractive"
export LC_CTYPE="en_US.UTF-8"

apt-get $APT_OPTIONS update
apt-get $APT_OPTIONS upgrade -y
apt-get $APT_OPTIONS dist-upgrade -y
locale-gen en_US.UTF-8
dpkg-reconfigure locales
apt-get $APT_OPTIONS install apt-transport-https ca-certificates curl software-properties-common -y
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
apt-get $APT_OPTIONS update
apt-get $APT_OPTIONS install docker-ce -y

groupadd {{ GROUP_NAME }} || true
usermod -aG docker {{ USERNAME }}
curl -L "https://github.com/docker/compose/releases/download/1.22.0/docker-compose-$(uname -s)-$(uname -m)" -o $DOCKER_COMPOSE_BIN
chmod +x $DOCKER_COMPOSE_BIN
exit 0
