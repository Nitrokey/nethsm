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

# API-only cert: no IP addresses
csr2=$(POST_admin /v1/config/tls/csr.pem <<EOM
{ "countryName": "DE",
  "stateOrProvinceName": "",
  "localityName": "Berlin",
  "organizationName": "Nitrokey",
  "organizationalUnitName": "",
  "commonName": "nethsm",
  "emailAddress": "info@nitrokey.com",
  "subjectAltNames": [ "nethsm1", "nethsm2", "nethsm3", "nethsm4", "nethsm5", "nethsm6", "nethsm7", "nethsm8" ]
}
EOM
)

echo "- API: create CA and sign CSR with it"
make -f cert.make clean
echo "$csr2" > nethsm.csr
make -f cert.make new_cert.pem
cp CA.pem api.pem

echo "- API: install new cert"
${CURL} -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem "${NETHSM_URL}/v1/config/tls/cert.pem" \
    || exit 1

# From now on verify the peer certificate
[ "${NOCACERT}" = "1" ] || CURL="${CURL_BASE} --cacert api.pem"

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
cp CA.pem cluster.pem

echo "- install new cert"
${CURL} -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./new_cert.pem "${NETHSM_URL}/v1/cluster/tls/cert.pem" \
    || exit 1

# wait for certificate to be valid, due to different rounding
# the timestamp of the just-signed certificate could be in the future
sleep 1

echo "- install cluster CA"
# TODO: move the location of this config to /cluster/? or have it in both places,
# one of them an alias?
${CURL} -u admin:Administrator -H "Content-Type: application/x-pem-file" \
    -X PUT --data-binary @./CA.pem "${NETHSM_URL}/v1/cluster/tls/ca.pem" \
    || exit 1
echo

# check if etcd still healthy after restart
GET_admin /v1/cluster/members

