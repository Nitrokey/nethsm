#!/bin/sh -e

: ${UNLOCKPW:=unlockunlock}
: ${MODE:=unix}
: ${ETCD_HOST:?Please provide etcd host address}
: ${ETCD_PORT:=2379}
: ${ETCD_CA_CERT:=/run/secrets/ca_cert}
: ${ETCD_CLIENT_CERT:=/run/secrets/client_cert}
: ${ETCD_CLIENT_KEY:=/run/secrets/client_key}

KEYFENDER_IP="127.0.0.1"
TLS_PROXY_LISTEN_IP="127.0.0.1"
TLS_PROXY_LISTEN_PORT="2379"
DEVICE_KEY_FILE="/run/secrets/device_key"

if [ -e "$DEVICE_KEY_FILE" ] ; then
  KEYFENDER_DEVICE_KEY="--device-key=$(cat $DEVICE_KEY_FILE)"
fi

if [ -n "$DEBUG_LOG" ] ; then
  ETCD_DEBUG_LOG="--log-level debug"
  KEYFENDER_DEBUG_LOG="--logs=*:debug"
fi

if [ $MODE == "unikernel" ] ; then
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

    KEYFENDER_IP="192.168.1.1"
    TLS_PROXY_LISTEN_IP="169.254.169.2"
  else
    echo "The require tun and kvm devices were not found."
    exit 1
  fi
fi

/tlsproxy \
  -listen "$TLS_PROXY_LISTEN_IP:$TLS_PROXY_LISTEN_PORT" \
  -etcd "$ETCD_HOST:$ETCD_PORT" \
  -ca-cert "$ETCD_CA_CERT" \
  -client-cert "$ETCD_CLIENT_CERT" \
  -client-key "$ETCD_CLIENT_KEY" \
  2>&1 | sed "s/^/[tlsproxy] /" \
  &
TLS_PROXY_PID=$!

sleep 2
if ! (pgrep tlsproxy > /dev/null) ; then 
  echo "The TLS proxy failed to start. Terminating.";
  exit 1
fi

if [ $ADMINPW ] ; then
{ sleep 2
  curl -k -X POST https://$KEYFENDER_IP:8443/api/v1/provision \
  -H "content-type: application/json" \
  -d "{ adminPassphrase: \"$ADMINPW\",
        unlockPassphrase: \"$UNLOCKPW\",
        systemTime: \"$(date --utc +%Y-%m-%dT%H:%M:%S+00:00)\" }"
}&
fi

if [ $MODE == "unix" ] ; then
  /keyfender.unix \
    $KEYFENDER_DEVICE_KEY \
    $KEYFENDER_DEBUG_LOG &
else
  /solo5-hvt \
    --net:external=tap200 \
    --net:internal=tap201 \
    /keyfender.hvt \
    $KEYFENDER_DEVICE_KEY \
    $KEYFENDER_DEBUG_LOG \
    &
fi
KEYFENDER_PID=$!

_signal_termination() {
  kill -TERM "$KEYFENDER_PID"
  kill -TERM "$TLS_PROXY_PID"
}

trap _signal_termination SIGTERM
trap _signal_termination SIGINT

wait "$KEYFENDER_PID"
wait "$TLS_PROXY_PID"
