#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

[ -z "$1" ] && echo "usage: $0 obj/update.img.bin" 1>&2 && exit 1
[ ! -f "$1" ] && echo "no such file: $1" 1>&2 && exit 1

echo "Updating."
url="${NITROHSM_URL}/v1/system/update"
echo "POST ${url}" 1>&2
curl -k -X POST -H 'Content-Type: application/octet-stream' \
    --user admin:Administrator \
    --data-binary @$1 \
    ${url}
