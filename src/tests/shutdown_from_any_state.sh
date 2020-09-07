#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

STATE=$(GET /v1/health/state | jq -r '.state')
echo $STATE # should be Operational

if [ $STATE = "Locked" ]; then
  "$(dirname $0)/unlock.sh"
elif [ $STATE = "Unprovisioned" ]; then
  "$(dirname $0)/provision_test.sh"
fi

"$(dirname $0)/shutdown_test.sh"
