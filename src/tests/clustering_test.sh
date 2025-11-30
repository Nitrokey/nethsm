#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

STATE=$(GET /v1/health/state)
echo "- state: $STATE" # should be Operational

CLUSTER=$(GET_admin /v1/cluster/members)
echo "- cluster state: $CLUSTER"

echo -n "- openssl version: "
openssl version || true

echo "network configuration: "
ip a

echo "arch: "
uname -a

echo "- get cert csr"

csr=$(POST_admin /v1/config/tls/csr.pem <<EOM
{ "countryName": "DE", "stateOrProvinceName": "", "localityName": "Berlin", "organizationName": "Nitrokey", "organizationalUnitName": "", "commonName": "nethsm.local", "emailAddress": "info@nitrokey.com", "subjectAltNames": [ "example.com", "www.example.com" ] }
EOM
)

echo "- creating CA and signing csr"
make -f cert.make clean
echo "$csr" > nethsm.csr
make -f cert.make new_cert.pem

sleep 5 # clock drift

echo -n "- installing new cert... "
curl -fsS -w "%{http_code}" -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem -k "${NETHSM_URL}/v1/config/tls/cert.pem"
echo

echo -n "- installing cluster CA... "
curl -fsS -w "%{http_code}" -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./CA.pem -k "${NETHSM_URL}/v1/config/tls/cluster-ca.pem"
echo

# try a request to see if the restarted etcd is healthy

CLUSTER=$(GET_admin /v1/cluster/members)
echo "- cluster state: $CLUSTER"

body=$(POST_admin /v1/cluster/join <<EOM
[{"name": "", "urls": ["https://192.168.1.1:2380"]},
{"name": "witness", "urls": ["https://192.168.1.100:2380"]}]
EOM
) || true
echo "$body"

CLUSTER=$(GET_admin /v1/cluster/members)
echo "- cluster state: $CLUSTER"

echo "launch new witness etcd"

CLUSTER="witness=https://192.168.1.100:2380"

rm -rf witness.etcd
etcd_name="etcd-v3.6.5-linux-arm64"
tar xvf "$etcd_name.tar.gz"

make -f cert.make own.pem

"$etcd_name/etcd" \
    --log-format console \
    --log-level warn \
    --initial-cluster "$CLUSTER" \
    --peer-client-cert-auth=true \
    --peer-trusted-ca-file=CA.pem \
    --peer-cert-file=own.pem \
    --peer-key-file=own.key \
    --data-dir=witness.etcd --name witness \
    --initial-advertise-peer-urls https://192.168.1.100:2380 --listen-peer-urls https://0.0.0.0:2380 \
    --advertise-client-urls "" --listen-client-urls http://0.0.0.0:2379 &

sleep 5

body=$(POST_admin /v1/cluster/join <<EOM
[{"name": "", "urls": ["https://192.168.1.1:2380"]},
{"name": "witness", "urls": ["https://192.168.1.100:2380"]}]
EOM
) || true
echo "$body"

sleep 20

STATE=$(GET /v1/health/state)
echo "- state: $STATE" # should be Operational

# try a request to see if the restarted etcd is healthy

CLUSTER=$(GET_admin /v1/cluster/members)
echo "- cluster state: $CLUSTER"
