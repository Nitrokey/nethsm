#!/usr/bin/env bash

source "$(dirname $0)/common_functions.sh"

JOBS="${JOBS:-4}"
ITERS="${ITERS:-400}"
PARALLEL="parallel --halt now,fail=1 -n0 -j${JOBS}"

echo "Starting key generation test."
REQUEST=$(mktemp)
cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_admin /v1/keys/generate <<EOM
{ "mechanisms": ["RSA_Signature_PKCS1"], "algorithm": "RSA", "length": 2048 }
EOM
EOF
seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
rm ${REQUEST}

echo "Starting signing test."
REQUEST=$(mktemp)
cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/myKey1/sign <<EOM
{
  mode: "PKCS1",
  message: "SGkgQWxpY2UhIFBsZWFzZSBicmluZyBtYWxhY3DDtnJrw7ZsdCBmb3IgZGlubmVyIQo="
}
EOM
EOF
seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
rm ${REQUEST}

echo "Starting decryption test."
REQUEST=$(mktemp)
cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/myKey1/decrypt <<EOM
{
  mode: "PKCS1",
  encrypted: "ADLOB8thK6ZkeJByjG9u5kakO9dU/msVXPo1DvPkv0xp88AZq3hMx/YUctiniVprPdq7AaHNbXlbL2LSO61r0H1nnp7iqtORDFr1CiTmwol1NKz/q6RxjbWBAj5uVG7l59Dfq/AwqF7gzha36w4mt2Smh9Y0mY+q0Wl7oy87bPCqcj3QFFXyZ1poeFiUDxNgoKUV7CpmhtxGU9OYHhxvQKVq97/dnRiX07FoHr/90csVUWM0JtC2snVuCzfYnl4bbeWHG731rJ8XSoTj1dF0+lY+Qegrup8tSkVm52YQaDMXIeI8gO/zrnVmAettKGbLprmcqLkm3/ppud3Z+FD4/Q=="
}
EOM
EOF
seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
rm ${REQUEST}

echo "Starting random generation test."
REQUEST=$(mktemp)
cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/random <<EOM
{
  "length": 1024
}
EOM
EOF
seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
rm ${REQUEST}

