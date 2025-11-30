#!/bin/sh -e

: ${UNLOCKPW:=unlockunlock}

KEYFENDER_IP="192.168.1.1"
KEYFENDER_INT_IP="169.254.169.1"
ETCD_IP="169.254.169.2"
ETCD_PORT="2379"

if [ -n "$DEBUG_LOG" ] ; then
  echo "Setting up debug logs."
  ETCD_DEBUG_LOG="--log-level debug"
  KEYFENDER_DEBUG_LOG="--logs=*:debug"
fi

if capsh --has-p=cap_net_admin 2>/dev/null ; then
  echo "Using Mirage TCP/IP stack with tap devices."
  mkdir -p /dev/net
  mknod /dev/net/tun c 10 200
  if [ -e /sys/class/net/eth1 ] ; then
    echo "Using eth1 as internal network."
    INT_IF="eth1"
  fi
else
  echo "need --cap-add=NET_ADMIN"
fi

  echo "Setting up bridge with eth0 and tap_ext."
  ip -o -f inet address show eth0
  IP=192.168.1.1/24
  ip tuntap add dev tap_ext mode tap
  ip addr add 192.168.1.100/24 dev tap_ext
  ip link set dev tap_ext up

  ip tuntap add dev tap_int mode tap
  if [ $INT_IF ] ; then
    echo "Setting up bridge with eth1 and tap_int."
    ip addr flush dev eth1
    ip link add name br_int type bridge
    ip link set dev $INT_IF master br_int
    ip link set dev tap_int master br_int
    ip link set dev eth1 type bridge_slave learning off
    ip link set dev br_int up
  else
    echo "Configuring tap_int for etcd."
    ip addr add 169.254.169.2/16 dev tap_int
  fi
  ip link set dev tap_int up

screen -dmS nethsm_debug
screen -S nethsm_debug -X hardstatus alwayslastline
screen -S nethsm_debug -X hardstatus string '%{= kG}[ %{G}%H %{g}][%= %{= kw}%?%-Lw%?%{r}(%{W}%n*%f%t%?(%u)%?%{r})%{w}%?%+Lw%?%?%= %{g}][%{B} %m-%d %{W}%c %{g}]'

if [ ! $INT_IF ]; then
screen -S nethsm_debug -X screen -t "etcd" \
  etcd \
    --listen-client-urls "http://$ETCD_IP:$ETCD_PORT" \
    --advertise-client-urls "http://$ETCD_IP:$ETCD_PORT" \
    --data-dir /data \
    --host-whitelist "$KEYFENDER_INT_IP" \
    --max-txn-ops 512 \
    $ETCD_DEBUG_LOG
fi

if [ $ADMINPW ] ; then
{ sleep 2
  echo "Provisioning NetHSM."
  curl -k -X POST https://$KEYFENDER_IP:8443/api/v1/provision \
  -H "content-type: application/json" \
  -d "{ adminPassphrase: \"$ADMINPW\",
        unlockPassphrase: \"$UNLOCKPW\",
        systemTime: \"$(date --utc +%Y-%m-%dT%H:%M:%S+00:00)\" }"
}&
fi


screen -S nethsm_debug -X screen -t "nethsm" \
  /keyfender.tap $KEYFENDER_DEBUG_LOG --platform=169.254.169.2 \
    --external-interface=tap_ext --internal-interface=tap_int \
    --internal-ipv4=169.254.169.1/16 --start


screen -S nethsm_debug -X screen -t "tcpdump" tcpdump -i tap_ext -e -v -n

screen -S nethsm_debug -X screen -t "shell" bash

_signal_termination() {
  kill -TERM "$KEYFENDER_PID"
  [ $ETCD_PID ] && kill -TERM "$ETCD_PID"
}

trap _signal_termination SIGTERM
trap _signal_termination SIGINT

screen -r nethsm_debug
