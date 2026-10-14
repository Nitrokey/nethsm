#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

echo
echo "=== Setup cluster CA ==="
echo

STATE=$(GET /v1/health/state)
if [[ "$STATE" != *Operational* ]] ; then
  echo "State $STATE != Operational"
  exit 1
fi


csr=$(POST_admin /v1/cluster/tls/csr.pem <<EOM
{ "countryName": "DE",
  "stateOrProvinceName": "",
  "localityName": "Berlin",
  "organizationName": "Nitrokey",
  "organizationalUnitName": "",
  "commonName": "nethsm",
  "emailAddress": "info@nitrokey.com",
  "subjectAltNames": [ "IP:192.168.1.1", "IP:169.254.169.1", "IP:172.22.1.2", "IP:172.22.1.3", "IP:172.22.1.4", "IP:172.22.1.5", "IP:172.22.1.6", "IP:172.22.1.7", "IP:172.22.1.8", "IP:172.22.1.9", "IP:fc00:22:1::2" ]
}
EOM
)
  
echo "- create CA and sign CSR with it"
make -f cert.make clean
echo "$csr" > nethsm.csr
make -f cert.make new_cert.pem

echo "- install new cert"
${CURL} -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem "${NETHSM_URL}/v1/cluster/tls/cert.pem" \
    || exit 1

sleep 3

echo "- install cluster CA"
# TODO: move the location of this config to /cluster/? or have it in both places,
# one of them an alias?
${CURL} -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./CA.pem "${NETHSM_URL}/v1/cluster/tls/ca.pem" \
    || exit 1
echo

# check if etcd still healthy after restart
GET_admin /v1/cluster/members

# API-only cert: no IP addresses
csr2=$(POST_admin /v1/config/tls/csr.pem <<EOM
{ "countryName": "DE",
  "stateOrProvinceName": "",
  "localityName": "Berlin",
  "organizationName": "Nitrokey",
  "organizationalUnitName": "",
  "commonName": "nethsm",
  "emailAddress": "info@nitrokey.com"
}
EOM
)

echo "- create CA and sign CSR with it"
make -f cert.make clean
echo "$csr2" > nethsm.csr
make -f cert.make new_cert.pem

echo "- install new cert"
${CURL} -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem "${NETHSM_URL}/v1/config/tls/cert.pem" \
    || exit 1

