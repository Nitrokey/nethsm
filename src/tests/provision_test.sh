#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

# provision hsm
echo "Provisioning."
SYSTEM_TIME="$(date -u +%FT%TZ)"
POST /v1/provision <<EOM
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

PUT_admin /v1/users/operator/tags/frankfurt <<EOM
EOM

PUT_admin /v1/users/operator/tags/berlin <<EOM
EOM

# create backup
PUT_admin /v1/users/backup <<EOM
{
  realName : "backup",
  role: "Backup",
  passphrase: "BackupBackup"
}
EOM

# create metrics
PUT_admin /v1/users/metrics <<EOM
{
  realName : "metrics",
  role: "Metrics",
  passphrase: "MetricsMetrics"
}
EOM

USERS=$(GET_admin /v1/users)
echo $USERS # should be admin, operator, backup, metrics
echo

# put a sign decrypt key
PUT_admin /v1/keys/myKey1 <<EOM
{
  mechanisms: ["RSA_Decryption_RAW", "RSA_Decryption_PKCS1", "RSA_Decryption_OAEP_MD5", "RSA_Decryption_OAEP_SHA1", "RSA_Decryption_OAEP_SHA224", "RSA_Decryption_OAEP_SHA256", "RSA_Decryption_OAEP_SHA384", "RSA_Decryption_OAEP_SHA512", "RSA_Signature_PKCS1", "RSA_Signature_PSS_MD5", "RSA_Signature_PSS_SHA1", "RSA_Signature_PSS_SHA224", "RSA_Signature_PSS_SHA256", "RSA_Signature_PSS_SHA384", "RSA_Signature_PSS_SHA512"],
  type: "RSA",
  key: {
    primeP: "APWssfg0uM2HevzjbDM+Om8ThaGLNoxzJkujtbT55SPhx5ntnDiktTXNRAHdwJgAc1HPVVCm6nESSIZ0ZqO+rh2vRYT+oXMHre0zhpGDZMVAB31zowTUv+6d7lakMbqN3hDjpxaiP3Xg7my4qMCrnnFyBq7LuE/0zw2SeoQnKlY1",
    primeQ : "ANAc/C1uKDdSsgc/du5N4B8vLZH8aC+poVyq8eZwkgs71vG3XccW6gEkC5dh439DKdZKYj3pywq39NNjzAK0VSs9TnscttaVtaS45rctpyP5nNoQnsVe3euc55P9UKuV9tRw7nnSi0Tf1QDbphEP/bsXj7F4FG6McdheXLPzV7M7",
    publicExponent : "AQAB"
  }
}
EOM
echo "Setup complete."

