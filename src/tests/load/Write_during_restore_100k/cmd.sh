#!/bin/sh

# Launch big restore in background, on provisioned machine
curl --insecure -X POST --user admin:Administrator \
    -F arguments='{"backupPassphrase": "backupPassphrase"}' \
    -F backup=@../_big_100k.bin "https://localhost:8443/api/v1/system/restore" &

sleep 2 # ensure the restore has started

# try to add a key during restore, this should fail either
# because etcd is unavailable (load too high) or
# because it detects a restore is in progress
curl --insecure 'https://localhost:8443/api/v1/keys' -X POST   -H "Authorization: Basic YWRtaW46QWRtaW5pc3RyYXRvcg==" -H "Content-Type: application/json" --data "{\"mechanisms\":[\"RSA_Signature_PSS_SHA256\"],\"type\":\"RSA\",\"private\":{\"primeP\":\"AOnWFZ+JrI/xOXJU04uYCZOiPVUWd6CSbVseEYrYQYxc7dVroePshz29tc+VEOUP5T0O8lXMEkjFAwjW6C9QTAsPyl6jwyOQluMRIkdN4/7BAg3HAMuGd7VmkGyYrnZWW54sLWp1JD6XJG33kF+9OSar9ETPoVyBgK5punfiUFEL\",\"primeQ\":\"ANT1kWDdP9hZoFKT49dwdM/S+3ZDnxQa7kZk9p+JKU5RaU9e8pS2GOJljHwkES1FH6CUGeIaUi81tRKe2XZhe/163sEyMcxkaaRbBbTc1v6ZDKILFKKt4eX7LAQfhL/iFlgi6pcyUM8QDrm1QeFgGz11ChM0JuQw1WwkX06lg8iv\",\"publicExponent\":\"AQAB\"},\"restrictions\":{\"tags\":[\"berlin\"]}}" -D headers.out -o body.out
