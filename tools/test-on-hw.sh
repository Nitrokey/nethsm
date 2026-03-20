#!/bin/bash -e

echo "- waiting for NetHSM"
x=0
while ! curl -m 1 -s -k -f https://192.168.1.1/api/v1/health/state ; do
    printf "."
    ((x++>25)) && echo "time out!" && exit 1
    sleep 2
done
echo "done."

cd src/tests

SYSTEM_TIME="$(date -u +%FT%TZ)"

echo "- restoring V0 backup"
curl -s -k -X POST -F arguments='{"backupPassphrase":"backupPassphrase","systemTime":"'${SYSTEM_TIME}'"}' \
    -F backup=@backup_v0_201.bin \
    https://192.168.1.1/api/v1/system/restore

echo "- unlocking"
curl -s -k -d '{"passphrase": "UnlockPassphrase"}' https://192.168.1.1/api/v1/unlock

echo "- reboot to enable new network config"
curl -s -k -X POST https://admin:Administrator@192.168.1.1/api/v1/system/reboot

echo "waiting for NetHSM"
x=0
while ! curl -m 1 -s -k -f https://192.168.1.201/api/v1/health/state ; do
    printf "."
    ((x++>25)) && echo "time out!" && exit 1
    sleep 2
done
echo "done."

echo "- unlocking"
curl -s -k -d '{"passphrase": "UnlockPassphrase"}' https://192.168.1.201/api/v1/unlock

NETHSM_URL="https://192.168.1.201/api" ./backup_restore.sh
NETHSM_URL="https://192.168.1.1/api" ./setup_cluster_ca.sh

curl -s -k -X PUT -H "content-type: application/json" -d \
    '{"ipAddress":"0.0.0.0","port":0,"logLevel":"warning"}' \
    https://admin:Administrator@192.168.1.1/api/v1/config/logging

flock /tmp/perftest.lock go run ./perftest.go -host 192.168.1.1:443 -j 50 \
    p256 p384 p521 rsa1024 rsa2048 rsa3072 rsa4096 ed25519 p256k1 \
    p256k1-bip340 brainpoolp256 brainpoolp384 brainpoolp512 aes-cbc rnd-1024 \
    p256-gen rsa2048-gen rsa3072-gen rsa4096-gen

curl -s -k -X PUT -H "content-type: application/json" -d \
    '{"ipAddress":"0.0.0.0","port":0,"logLevel":"info"}' \
    https://admin:Administrator@${NETHSM_IP}/api/v1/config/logging

NETHSM_URL="https://${NETHSM_IP}/api" ./hw_tests.sh
