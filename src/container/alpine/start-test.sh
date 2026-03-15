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
fi

if [ $USE_TAP ] ; then
  echo "Setting up tap devices"
  ip -o -f inet address show eth0
  IP=$(ip -o -f inet address show eth0 | awk '{print $4}' | head -1)
  echo "Detected IP: $IP"
  GW=$(ip -o -f inet route list | grep "^default via" | head -1 | awk '{print $3}')
  echo "Detected gateway: $GW"

  ip tuntap add dev tap_int mode tap
  ip tuntap add dev tap_ext mode tap
  ip addr add 169.254.169.2/24 dev tap_int
  ip addr add 169.254.100.1/24 dev tap_ext
  ip link set dev tap_int up
  ip link set dev tap_ext up

  ip addr add 169.254.200.2/24 dev lo
  ip -6 addr add fc00:1:200::2/120 dev lo

  echo "Starting mock S-Net"
  /uinit net_external 2>&1 &
  echo "Starting mock S-Platform"
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
    --internal-ipv4=169.254.169.1/24 --start &
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
