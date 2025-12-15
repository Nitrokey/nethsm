#!/bin/sh -e

: ${UNLOCKPW:=unlockunlock}

KEYFENDER_IP="127.0.0.1"
KEYFENDER_INT_IP="127.0.0.1"
PLATFORM_IP="127.0.0.1"
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
  USE_TAP=1
  KEYFENDER_IP="192.168.1.1"
  PLATFORM_IP="169.254.169.2"
  KEYFENDER_INT_IP="169.254.169.1"
  if [ -e /sys/class/net/eth1 ] ; then
    echo "Using eth1 as internal network."
    INT_IF="eth1"
  fi
fi

if [ $USE_TAP ] ; then
  echo "Setting up bridge with eth0 and tap_ext."
  ip -o -f inet address show eth0
  IP=$(ip -o -f inet address show eth0 | awk '{print $4}' | head -1)
  echo "Detected IP: $IP"
  GW=$(ip -o -f inet route list | grep "^default via" | head -1 | awk '{print $3}')
  echo "Detected gateway: $GW"
  ip addr flush dev eth0
  ip tuntap add dev tap_ext mode tap
  ip link add name br_ext type bridge
  ip link set dev eth0 master br_ext
  ip link set dev tap_ext master br_ext
  ip link set dev eth0 type bridge_slave learning off
  ip link set dev br_ext up
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
    echo "Configuring tap_int for platform."
    ip addr add 169.254.169.2/16 dev tap_int
  fi
  ip link set dev tap_int up
  ip route add default via 169.254.169.1 dev tap_int
fi

if [ ! $INT_IF ]; then
  if [ $USE_TAP ] ; then
    echo "Starting uinit on $PLATFORM_IP."
    /uinit platform 2>&1 &
  else
    echo "Starting etcd on $PLATFORM_IP."
    etcd \
      --listen-client-urls "http://$PLATFORM_IP:$ETCD_PORT" \
      --advertise-client-urls "http://$PLATFORM_IP:$ETCD_PORT" \
      --data-dir /data \
      --host-whitelist "$KEYFENDER_INT_IP" \
      --max-txn-ops 512 \
      $ETCD_DEBUG_LOG \
      2>&1 | sed "s/^/[etcd] /" \
      &
    ETCD_PID=$!
  fi
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

if [ $GW ] ; then
  IP="$IP,$GW"
fi

if [ $USE_TAP ] ; then
  echo "Starting keyfender.tap"
  /keyfender.tap $KEYFENDER_DEBUG_LOG --default-net=$IP --platform=169.254.169.2 \
    --external-interface=tap_ext --internal-interface=tap_int \
    --internal-ipv4=169.254.169.1/16 --start &
  KEYFENDER_PID=$!
else
  echo "Starting keyfender.unix"
  /keyfender.unix $KEYFENDER_DEBUG_LOG --http=8080 --https=8443 --platform=127.0.0.1 --start &
  KEYFENDER_PID=$!
fi

_signal_termination() {
  kill -TERM "$KEYFENDER_PID"
  [ $ETCD_PID ] && kill -TERM "$ETCD_PID"
}

trap _signal_termination SIGTERM
trap _signal_termination SIGINT

wait "$KEYFENDER_PID"
[ $ETCD_PID ] && wait "$ETCD_PID"
