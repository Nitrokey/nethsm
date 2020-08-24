#!/usr/bin/env bash

source common_functions.sh

# start a hsm test server 
# keyfender/_build/default/test/test_server.exe

# provision hsm
echo "Provisioning."
SYSTEM_TIME="$(date --utc +%FT%TZ)"
PUT /v1/provision <<EOM
{ 
  "unlockPassphrase": "UnlockPassphrase",
  "adminPassphrase": "Administrator",
  "systemTime": "${SYSTEM_TIME}"
}
EOM

STATE=$(GET /v1/health/state)
echo $STATE # should be Operational
echo

# create operator
PUT_admin /v1/users/operator <<EOM
{
  realName : "operator",
  role: "Operator",
  passphrase: "OperatorOperator"
}
EOM

USERS=$(GET_admin /v1/users)
echo $USERS # should be admin and operator
echo

# put a sign decrypt key
PUT_admin /v1/keys/myKey1 <<EOM
{
  purpose: "SignAndDecrypt",
  algorithm: "RSA",
  key: {
    primeP: "APWssfg0uM2HevzjbDM+Om8ThaGLNoxzJkujtbT55SPhx5ntnDiktTXNRAHdwJgAc1HPVVCm6nESSIZ0ZqO+rh2vRYT+oXMHre0zhpGDZMVAB31zowTUv+6d7lakMbqN3hDjpxaiP3Xg7my4qMCrnnFyBq7LuE/0zw2SeoQnKlY1",
    primeQ : "ANAc/C1uKDdSsgc/du5N4B8vLZH8aC+poVyq8eZwkgs71vG3XccW6gEkC5dh439DKdZKYj3pywq39NNjzAK0VSs9TnscttaVtaS45rctpyP5nNoQnsVe3euc55P9UKuV9tRw7nnSi0Tf1QDbphEP/bsXj7F4FG6McdheXLPzV7M7",
    publicExponent : "AQAB"
  }
}
EOM
echo "Setup compete."

