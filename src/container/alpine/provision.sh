#!/bin/sh

curl -k -v "https://nethsm1:443/api/v1/provision" -X POST   -d '{"unlockPassphrase":"UnlockPassphrase","adminPassphrase":"Administrator","systemTime":"'$(date -u "+%Y-%m-%dT%H:%M:%SZ")'"}'

curl -k -v "https://admin:Administrator@nethsm1:443/api/v1/users/operator" -H "Content-Type: application/json" -X PUT -d '{"realName":"operator","role":"Operator","passphrase":"OperatorOperator"}'
