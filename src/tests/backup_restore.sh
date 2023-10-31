#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Operational* ]] ; then
  echo "State $STATE != Operational"
  exit 1
fi

echo "doing reboot"
POST_admin /v1/system/reboot

echo "waiting for NetHSM"
x=0
while ! curl -s -k -f https://${NETHSM_IP}/api/v1/health/state ; do
  printf "."
  ((x++>10)) && echo "time out!" && exit 1
  sleep 5
done
echo

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Locked* ]] ; then
  echo "State $STATE != Locked"
  exit 1
fi

echo "unlocking"
POST /v1/unlock <<EOM
{
  "passphrase": "UnlockPassphrase"
}
EOM

echo "creating backup"
POST /v1/system/backup --user backup:BackupBackup -o /tmp/backup.bin

echo "doing factory reset"
POST_admin /v1/system/factory-reset

echo "waiting for NetHSM"
x=0
while ! curl -s -k -f https://${NETHSM_IP}/api/v1/health/state ; do
  printf "."
  ((x++>10)) && echo "time out!" && exit 1
  sleep 5
done
echo

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Unprovisioned* ]] ; then
  echo "State $STATE != Unprovisioned"
  exit 1
fi

echo "restoring backup"
${CURL} -X POST -H "Content-Type: application/octet-stream" --data-binary @/tmp/backup.bin \
  https://${NETHSM_IP}/api/v1/system/restore?backupPassphrase=backupPassphrase || exit 1

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Locked* ]] ; then
  echo "State $STATE != Locked"
  exit 1
fi

echo "unlocking"
POST /v1/unlock <<EOM
{
  "passphrase": "UnlockPassphrase"
}
EOM

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Operational* ]] ; then
  echo "State $STATE != Operational"
  exit 1
fi

echo "System ready."
