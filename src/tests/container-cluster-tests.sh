#!/usr/bin/env bash

N1=https://172.22.1.2
N2=https://172.22.1.3
N3=https://172.22.1.4
N4=https://172.22.1.5
EW=https://172.22.1.10

SYSTEM_TIME="$(date -u +%FT%TZ)"

# Provision and install cert with same CA in N1, N2, N3
NETHSM_URL="$N1/api"
source ./provision_test.sh
source ./cluster_ca.sh

NETHSM_URL="$N2/api"
source ./provision_test.sh
source ./cluster_ca.sh

NETHSM_URL="$N3/api"
source ./provision_test.sh
source ./cluster_ca.sh

# Register N2 in N1
NETHSM_URL="$N1/api"
source ./common_functions.sh

resp=$(POST_admin /v1/cluster/members <<EOF
{"urls": ["$N2:2380"] }
EOF
)

join_req=$(echo "$resp" | jq '.+={"backupPassphrase": "backupPassphrase"}')
echo "join req: $join_req"

# N2 join N1 with the info from last request
NETHSM_URL="$N2/api"
source ./common_functions.sh

echo "attempt to join, this may take some time"
POST_admin /v1/cluster/join <<EOF
$join_req
EOF

GET /v1/health/state # should be Locked

POST_admin /v1/unlock <<EOF
{"passphrase": "UnlockPassphrase"}
EOF

GET /v1/health/state # should be Operational

# should be able to see a key from N1
GET_admin /v1/keys/myKey1 # should not 404

# let's create a key here, it should be visible on the other side afterwards
POST_admin /v1/keys/generate <<EOF
{
  "mechanisms": [
    "RSA_Signature_PSS_SHA256"
  ],
  "type": "RSA",
  "length": 2048,
  "id": "keyAcrossCluster"
}
EOF

# let's check N1 is still alive and can see the newly created key
NETHSM_URL="$N1/api"
source ./common_functions.sh

GET_admin /v1/health/state # should be Operational
GET_admin /v1/keys/keyAcrossCluster # should not 404

# let's add a third node, from N2

resp=$(POST_admin /v1/cluster/members <<EOF
{"urls": ["$N3:2380"] }
EOF
)

join_req=$(echo "$resp" | jq '.+={"backupPassphrase": "backupPassphrase"}')
echo "join req: $join_req"

# N2 join N1 with the info from last request
NETHSM_URL="$N3/api"
source ./common_functions.sh

echo "attempt to join again, this may take some time"
POST_admin /v1/cluster/join <<EOF
$join_req
EOF

POST_admin /v1/unlock <<EOF
{"passphrase": "UnlockPassphrase"}
EOF

# let's create yet another key
POST_admin /v1/keys/generate <<EOF
{
  "mechanisms": [
    "RSA_Signature_PSS_SHA256"
  ],
  "type": "RSA",
  "length": 2048,
  "id": "keyN3"
}
EOF

# N2 should have automatically joined with N3 as well, should see the key
NETHSM_URL="$N2/api"
source ./common_functions.sh

GET_admin /v1/keys/keyN3 # should not 404

GET_admin /v1/cluster/members

echo "Clustering tests OK!"
