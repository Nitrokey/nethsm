#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

url="${NETHSM_URL}/v1/system/commit-update"
echo "POST ${url}" 1>&2
curl -k -X POST -H 'Content-Type: application/octet-stream' \
    --user admin:Administrator \
    ${url}
