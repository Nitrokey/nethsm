#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Operational* ]] ; then
  echo "State $STATE != Operational"
  exit 1
fi

# echo "doing reboot"
# POST_admin /v1/system/reboot

# echo "waiting for NetHSM"
# x=0
# while ! curl -m 1 -s -k -f https://${NETHSM_IP}/api/v1/health/state ; do
#   printf "."
#   ((x++>25)) && echo "time out!" && exit 1
#   sleep 2
# done
# echo

# STATE=$(GET /v1/health/state)
# if [[ "$STATE" != *Locked* ]] ; then
#   echo "State $STATE != Locked"
#   exit 1
# fi

# echo "unlocking"
# POST /v1/unlock <<EOM
# {
#   "passphrase": "UnlockPassphrase"
# }
# EOM

echo "creating backup"
POST /v1/system/backup --user backup:BackupBackup -o backup.bin

echo "doing factory reset"
POST_admin /v1/system/factory-reset

echo "waiting for NetHSM"
x=0
while ! curl -m 1 -s -k -f https://${NETHSM_IP}/api/v1/health/state ; do
  printf "."
  ((x++>25)) && echo "time out!" && exit 1
  sleep 2
done
echo

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Unprovisioned* ]] ; then
  echo "State $STATE != Unprovisioned"
  exit 1
fi

# provision hsm differently
echo "Provisioning again differently."
SYSTEM_TIME="$(date -u +%FT%TZ)"
POST /v1/provision <<EOM
{
  "unlockPassphrase": "UnlockPassphrase2",
  "adminPassphrase": "Administrator2",
  "systemTime": "${SYSTEM_TIME}"
}
EOM

echo "restoring backup"
${CURL} -X POST --user admin:Administrator2 -F arguments='{"backupPassphrase": "backupPassphrase"}' -F backup=@backup.bin \
  https://${NETHSM_IP}/api/v1/system/restore || exit 1


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

echo "restoring backup again"
${CURL} -X POST --user admin:Administrator -F arguments='{"backupPassphrase": "backupPassphrase"}' -F backup=@backup.bin \
  https://${NETHSM_IP}/api/v1/system/restore || exit 1

# should be directly operational
STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Operational* ]] ; then
  echo "State $STATE != Operational"
  exit 1
fi

echo "System ready."

echo "Backup dump:"
python3 ../keyfender/bin/export_backup.py backupPassphrase backup.bin
