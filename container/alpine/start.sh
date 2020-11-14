#!/bin/sh -e

if [ ! -e /dev/net/tun -o ! -e /dev/kvm ] ; then
  echo "Please run container with these arguments:"
  echo "--device=/dev/kvm:/dev/kvm"
  echo "--device=/dev/net/tun:/dev/net/tun"
  echo "--cap-add=NET_ADMIN"
  exit
fi

tunctl -t tap200
ip addr add 192.168.1.100/24 dev tap200
ip link set dev tap200 up

tunctl -t tap201
ip addr add 169.254.169.2/24 dev tap201
ip link set dev tap201 up

iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp --dport 8443 \
  -j DNAT --to-destination 192.168.1.1:443 
iptables -t nat -A POSTROUTING -o tap200 -j SNAT --to-source 192.168.1.100

if [ ! -d /data/keyfender-data.git ] ; then
  mkdir /data/keyfender-data.git
  git init --bare /data/keyfender-data.git
fi

git daemon \
    --listen=169.254.169.2 \
    --base-path=/data \
    --export-all \
    --enable=receive-pack \
    &

/solo5-hvt \
    --net:external=tap200 \
    --net:internal=tap201 \
    /keyfender.hvt
