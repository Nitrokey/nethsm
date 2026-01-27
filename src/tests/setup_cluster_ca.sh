#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

STATE=$(GET /v1/health/state)
echo "- state: $STATE" # should be Operational

echo "- get cert csr"

csr=$(POST_admin /v1/config/tls/csr.pem <<EOM
{ "countryName": "DE",
  "stateOrProvinceName": "",
  "localityName": "Berlin",
  "organizationName": "Nitrokey",
  "organizationalUnitName": "",
  "commonName": "nethsm",
  "emailAddress": "info@nitrokey.com",
  "subjectAltNames": [ "IP:192.168.1.1", "IP:169.254.169.1", "IP:172.22.1.2", "IP:172.22.1.3", "IP:172.22.1.4" ]
}
EOM
)
  

echo "- creating CA and signing csr"
make -f cert.make clean
echo "$csr" > nethsm.csr
make -f cert.make new_cert.pem

echo -n "- installing new cert... "
curl -fsS -w "%{http_code}" -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem -k "${NETHSM_URL}/v1/config/tls/cert.pem"
echo

sleep 3

echo -n "- installing cluster CA... "
curl --fail-with-body -sS -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./CA.pem -k "${NETHSM_URL}/v1/config/tls/cluster-ca.pem"
echo

echo -n "- HSM still healthy after etcd restart: "
GET_admin /v1/cluster/members
