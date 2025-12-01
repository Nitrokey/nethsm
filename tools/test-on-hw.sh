#!/bin/bash -e

echo "waiting for NetHSM"
x=0
while ! curl -m 1 -s -k -f https://${NETHSM_IP}/api/v1/health/state ; do
    printf "."
    ((x++>25)) && echo "time out!" && exit 1
    sleep 2
done
echo "done."

etcd_download=$(pwd)/etcd-download
rm -rf "$etcd_download"
make USE_CCACHE= -i "$etcd_download"

cd src/tests
NETHSM_URL="https://${NETHSM_IP}/api" ./provision_test.sh
#NETHSM_URL="https://${NETHSM_IP}/api" ./backup_restore.sh
NETHSM_URL="https://${NETHSM_IP}/api" ./cluster_ca.sh
NETHSM_URL="https://${NETHSM_IP}/api" ./clustering_test.sh

curl -s -k -X PUT -H "content-type: application/json" -d \
    '{"ipAddress":"0.0.0.0","port":0,"logLevel":"info"}' \
    https://admin:Administrator@${NETHSM_IP}/api/v1/config/logging

#flock /tmp/perftest.lock go run ./perftest.go -host ${NETHSM_IP}:443 -j 10 \
#    p256 p384 p521 rsa1024 rsa2048 rsa3072 rsa4096 ed25519 p256k1 \
#    p256k1-bip340 brainpoolp256 brainpoolp384 brainpoolp512 aes-cbc rnd-1024 \
#    p256-gen rsa2048-gen rsa3072-gen rsa4096-gen
