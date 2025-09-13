#!/bin/sh -e

: ${UNLOCKPW:=unlockunlock}

KEYFENDER_IP="127.0.0.1"
ETCD_IP="127.0.0.1"
ETCD_PORT="2379"

if [ -n "$DEBUG_LOG" ] ; then
  ETCD_DEBUG_LOG="--log-level debug"
  KEYFENDER_DEBUG_LOG="--logs=*:debug"
fi

etcd \
  --listen-client-urls "http://$ETCD_IP:$ETCD_PORT" \
  --advertise-client-urls "http://$ETCD_IP:$ETCD_PORT" \
  --data-dir /data \
  --host-whitelist "$KEYFENDER_IP" \
  --max-txn-ops 512 \
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

/keyfender.unix $KEYFENDER_DEBUG_LOG --http=8080 --https=8443 --platform=127.0.0.1 --start &
KEYFENDER_PID=$!

_signal_termination() {
  kill -TERM "$KEYFENDER_PID"
  kill -TERM "$ETCD_PID"
}

trap _signal_termination SIGTERM
trap _signal_termination SIGINT

wait "$KEYFENDER_PID"
wait "$ETCD_PID"
