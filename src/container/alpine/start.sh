#!/bin/sh -e

: ${UNLOCKPW:=unlockunlock}

KEYFENDER_IP="127.0.0.1"
ETCD_IP="127.0.0.1"

if [ -n "$DEBUG_LOG" ] ; then
  ETCD_DEBUG_LOG="--log-level debug"
  KEYFENDER_DEBUG_LOG="--logs=*:debug"
fi

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

  KEYFENDER_KVM=1
  KEYFENDER_IP="192.168.1.1"
  ETCD_IP="169.254.169.2"
fi

etcd \
    --listen-client-urls "http://$ETCD_IP:2379" \
    --advertise-client-urls "http://$ETCD_IP:2379" \
    --data-dir /data \
    --host-whitelist "$KEYFENDER_IP" \
    $ETCD_DEBUG_LOG \
    2>&1 | sed "s/^/[etcd] /" \
    &

ETCD_PID=$!

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
/keyfender.unix $KEYFENDER_DEBUG_LOG &
else
/solo5-hvt \
    --net:external=tap200 \
    --net:internal=tap201 \
    /keyfender.hvt $KEYFENDER_DEBUG_LOG \
    &
fi

KEYFENDER_PID=$!

_signal_termination() {
    kill -TERM "$KEYFENDER_PID"
    kill -TERM "$ETCD_PID"
}

trap _signal_termination SIGTERM
trap _signal_termination SIGINT

wait "$KEYFENDER_PID"
wait "$ETCD_PID"
