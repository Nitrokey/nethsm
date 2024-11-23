#!/bin/bash -e

echo "waiting for NetHSM"
x=0
while ! curl -m 1 -s -k -f https://${NETHSM_IP}/api/v1/health/state ; do
    printf "."
    ((x++>25)) && echo "time out!" && exit 1
    sleep 2
done
echo "done."

cd src/tests
NETHSM_URL="https://${NETHSM_IP}/api" ./provision_test.sh
NETHSM_URL="https://${NETHSM_IP}/api" ./backup_restore.sh

curl -s -k -X PUT -H "content-type: application/json" -d \
    '{"ipAddress":"0.0.0.0","port":0,"logLevel":"warning"}' \
    https://admin:Administrator@${NETHSM_IP}/api/v1/config/logging

flock /tmp/perftest.lock go run ./perftest.go -host ${NETHSM_IP}:443 -j 10 \
    p256 p384 p521 rsa2048 rsa4096 ed25519 aes-cbc rnd-1024 \
    p256-gen rsa2048-gen rsa4096-gen
