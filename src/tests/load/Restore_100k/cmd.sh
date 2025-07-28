#!/bin/sh
curl --insecure -X POST --user admin:Administrator \
    -F arguments='{"backupPassphrase": "backupPassphrase"}' \
    -F backup=@big_100k.bin "https://localhost:8443/api/v1/system/restore" \
    -D headers.out -o body.out

