#!/bin/sh -e

: ${UNLOCKPW:=unlockunlock}

KEYFENDER_IP=127.0.0.1

if [ -e /dev/net/tun -a -e /dev/kvm ] ; then
  tunctl -t tap200 >/dev/null
  ip addr add 192.168.1.100/24 dev tap200
  ip link set dev tap200 up

  tunctl -t tap201 >/dev/null
  ip addr add 169.254.169.2/24 dev tap201
  ip link set dev tap201 up

  iptables -t nat -A PREROUTING -i eth0 -p tcp -m tcp --dport 8443 \
    -j DNAT --to-destination 192.168.1.1:443
  iptables -t nat -A POSTROUTING -o tap200 -j SNAT --to-source 192.168.1.100

  GIT_LISTEN="--listen=169.254.169.2"
  KEYFENDER_KVM=1
  KEYFENDER_IP=192.168.1.1
fi

if [ ! -d /data/keyfender-data.git ] ; then
  git init --bare /data/keyfender-data.git -b master
fi

git daemon \
    $GIT_LISTEN \
    --base-path=/data \
    --export-all \
    --enable=receive-pack \
    &
if [ $ADMINPW ] ; then
{ sleep 2
  curl -k -X POST https://$KEYFENDER_IP:8443/api/v1/provision \
  -H "content-type: application/json" \
  -d "{ adminPassphrase: \"$ADMINPW\",
        unlockPassphrase: \"$UNLOCKPW\",
        systemTime: \"$(date --utc +%Y-%m-%dT%H:%M:%S+00:00)\" }"
}&
fi

if [ -z "$KEYFENDER_KVM" ] ; then
/keyfender.unix
else
/solo5-hvt \
    --net:external=tap200 \
    --net:internal=tap201 \
    /keyfender.hvt
fi
