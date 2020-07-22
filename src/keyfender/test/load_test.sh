#!/usr/bin/env bash

# start a hsm test server 
# keyfender/_build/default/test/test_server.exe

# provision hsm
echo "Provisioning."
curl -v -H "Content-Type: application/json" http://localhost:8080/api/v1/provision -X PUT --data @provision.json
STATE=$(curl http://localhost:8080/api/v1/health/state)
echo $STATE # should be Operational
echo

# create operator
curl -X PUT http://admin:Administrator@localhost:8080/api/v1/users/operator -v -H "Content-Type: application/json" --data "{ realName : \"operator\", role: \"Operator\", passphrase: \"OperatorOperator\" }"
USERS=$(curl http://admin:Administrator@localhost:8080/api/v1/users)
echo $USERS # should be admin and operator
echo

# generate signing key
curl -v -H "Content-Type: application/json" -X POST http://admin:Administrator@localhost:8080/api/v1/keys/generate --data @keys_generate.json
# put a decrypt key
curl -v -H "Content-Type: application/json" -X PUT http://admin:Administrator@localhost:8080/api/v1/keys/myKey1 --data '{ purpose: "Decrypt", algorithm: "RSA", key: { primeP: "APWssfg0uM2HevzjbDM+Om8ThaGLNoxzJkujtbT55SPhx5ntnDiktTXNRAHdwJgAc1HPVVCm6nESSIZ0ZqO+rh2vRYT+oXMHre0zhpGDZMVAB31zowTUv+6d7lakMbqN3hDjpxaiP3Xg7my4qMCrnnFyBq7LuE/0zw2SeoQnKlY1", primeQ : "ANAc/C1uKDdSsgc/du5N4B8vLZH8aC+poVyq8eZwkgs71vG3XccW6gEkC5dh439DKdZKYj3pywq39NNjzAK0VSs9TnscttaVtaS45rctpyP5nNoQnsVe3euc55P9UKuV9tRw7nnSi0Tf1QDbphEP/bsXj7F4FG6McdheXLPzV7M7", publicExponent : "AQAB" } }'

echo "Setup compete."

echo "Starting key generation test."
# 400 times, and 4 at a time
seq 400 | parallel -n0 -j4 "curl -X POST http://admin:Administrator@localhost:8080/api/v1/keys/generate --data @keys_generate.json -H \"Content-Type: application/json\""

echo "Starting decryption test."
# NOTE: only " in json and not '
seq 400 | parallel -n0 -j4 "curl -v -H 'Content-Type: application/json' -X POST http://operator:OperatorOperator@localhost:8080/api/v1/keys/myKey1/decrypt --data '{ mode: \"PKCS1\", encrypted: \"ADLOB8thK6ZkeJByjG9u5kakO9dU/msVXPo1DvPkv0xp88AZq3hMx/YUctiniVprPdq7AaHNbXlbL2LSO61r0H1nnp7iqtORDFr1CiTmwol1NKz/q6RxjbWBAj5uVG7l59Dfq/AwqF7gzha36w4mt2Smh9Y0mY+q0Wl7oy87bPCqcj3QFFXyZ1poeFiUDxNgoKUV7CpmhtxGU9OYHhxvQKVq97/dnRiX07FoHr/90csVUWM0JtC2snVuCzfYnl4bbeWHG731rJ8XSoTj1dF0+lY+Qegrup8tSkVm52YQaDMXIeI8gO/zrnVmAettKGbLprmcqLkm3/ppud3Z+FD4/Q==\"}'"

echo "Starting random genration test."
seq 400 | parallel -n0 -j4 "curl -X POST http://operator:OperatorOperator@localhost:8080/api/v1/random --data '{ \"length\": 1024 }'"
