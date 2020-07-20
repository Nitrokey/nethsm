#!/usr/bin/env bash

# start a hsm test server 
# keyfender/_build/default/test/test_server.exe

echo "Provisioning."

# provision hsm
curl -X PUT http://localhost:8080/api/v1/provision --data @provision.json -H "Content-Type: application/json" -v

# get state
curl http://localhost:8080/api/v1/health/state -H "Content-Type: application/json" -v
# already unlocked - do some work

echo "Starting key generation test."

# 400 times, and 4 at a time
seq 400 | parallel -n0 -j4 "curl -X POST http://admin:Administrator@localhost:8080/api/v1/keys/generate --data @keys_generate.json -H \"Content-Type: application/json\""

# TODO investigate with hannes why operator is not authorized
## generate one key for signing
#curl -X POST http://admin:Administrator@localhost:8080/api/v1/keys/key1 --data @keys_generate1.json -H "Content-Type: application/json"
#
#curl -X POST http://admin:Administrator@localhost:8080/api/v1/users --data @operator_user.json -H "Content-Type: application/json" -v
#
#curl -X POST http://operator:OperatorOperator@localhost:8080/api/v1/keys/key1/sign -H "Content-Type: application/json"
#
#curl -X POST http://operator:OperatorOperator@localhost:8080/api/v1/keys/generate --data @keys_generate.json -H "Content-Type: application/json" -v
#curl -X POST http://operator:OperatorOperator@localhost:8080/api/v1/random
