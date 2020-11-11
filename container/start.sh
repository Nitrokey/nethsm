#!/bin/sh -e

if [ ! -e /dev/net/tun -o ! -e /dev/kvm ] ; then
  echo "Please run container with these arguments:"
  echo "--device=/dev/kvm:/dev/kvm"
  echo "--device=/dev/net/tun:/dev/net/tun"
  echo "--cap-add=NET_ADMIN"
  exit
fi

/setup-net-dev.sh

if [ ! -d /data/keyfender-data.git ] ; then
  mkdir /data/keyfender-data.git
  git init --bare /data/keyfender-data.git
fi

simpleproxy -L 8443 -R 192.168.1.1:443 &

git-daemon \
    --listen=169.254.169.2 \
    --base-path=/data \
    --export-all \
    --enable=receive-pack \
    &

solo5-hvt \
    --net:external=tap200 \
    --net:internal=tap201 \
    /keyfender.hvt
