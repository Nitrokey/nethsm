#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

echo "Unlocking."
PUT /v1/unlock <<EOM
{ 
  "passphrase": "UnlockPassphrase"
}
EOM

STATE=$(GET /v1/health/state)
echo $STATE # should be Operational
echo

