#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

STATE=$(GET /v1/health/state)
echo "- state: $STATE" # should be Operational

CLUSTER=$(GET_admin /v1/cluster/members)
echo "- cluster state: $CLUSTER"

echo -n "- openssl version: "
openssl version || true

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
curl -s -w "%{http_code}" -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem -k "${NETHSM_URL}/v1/config/tls/cert.pem"
echo

echo -n "- installing cluster CA... "
curl -s -w "%{http_code}" -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./CA.pem -k "${NETHSM_URL}/v1/config/tls/cluster-ca.pem"
echo

sleep 5

USERS=$(GET_admin /v1/users)
echo "- users: $USERS" # should be admin, operator, backup, metrics
echo

POST_admin /v1/cluster/join <<<EOM
[{"name": "node1", "urls": ["http://192.168.1.1:2380"]},
{"name": "node2", "urls": ["http://192.168.1.2:2380", "http://[::1]:2380"]}]
EOM
