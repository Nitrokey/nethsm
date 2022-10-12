#!/usr/bin/env bash

set -e

CONNECTIONS="${CONNECTIONS:-10}"
REQUESTS="${REQUESTS:-1000}"
NETHSM_URL="${NETHSM_URL:-http://192.168.1.1/api}"

CURL="curl -f --fail-early -sS -k -w %{stderr}. --parallel --parallel-immediate --parallel-max ${CONNECTIONS}"

echo
echo "Starting load test with ${REQUESTS} requests and ${CONNECTIONS} parallel connections"
echo

mkconfig ()
{
  cat <<EOF >$1
header = "Content-Type: application/json"
user = $2
data = @-
EOF
  for i in $(seq ${REQUESTS}) ; do 
    echo "url = ${NETHSM_URL}$3" >> $1
  done
}

echo "Starting key generation test."
CONF=$(mktemp)
mkconfig ${CONF} admin:Administrator /v1/keys/generate
time ${CURL} --config ${CONF} 2>&1 >/dev/null <<EOM | fold -w 100
{ "mechanisms": ["RSA_Signature_PKCS1"], "type": "RSA", "length": 2048 }
EOM
echo
rm ${CONF}

echo
echo "Starting signing test."
CONF=$(mktemp)
mkconfig ${CONF} operator:OperatorOperator /v1/keys/myKey1/sign
time ${CURL} --config ${CONF} 2>&1 >/dev/null <<EOM | fold -w 100
{
  mode: "PKCS1",
  message: "SGkgQWxpY2UhIFBsZWFzZSBicmluZyBtYWxhY3DDtnJrw7ZsdCBmb3IgZGlubmVyIQo="
}
EOM
echo
rm ${CONF}

echo
echo "Starting decryption test."
CONF=$(mktemp)
mkconfig ${CONF} operator:OperatorOperator /v1/keys/myKey1/decrypt
time ${CURL} --config ${CONF} 2>&1 >/dev/null <<EOM | fold -w 100
{
  mode: "PKCS1",
  encrypted: "ADLOB8thK6ZkeJByjG9u5kakO9dU/msVXPo1DvPkv0xp88AZq3hMx/YUctiniVprPdq7AaHNbXlbL2LSO61r0H1nnp7iqtORDFr1CiTmwol1NKz/q6RxjbWBAj5uVG7l59Dfq/AwqF7gzha36w4mt2Smh9Y0mY+q0Wl7oy87bPCqcj3QFFXyZ1poeFiUDxNgoKUV7CpmhtxGU9OYHhxvQKVq97/dnRiX07FoHr/90csVUWM0JtC2snVuCzfYnl4bbeWHG731rJ8XSoTj1dF0+lY+Qegrup8tSkVm52YQaDMXIeI8gO/zrnVmAettKGbLprmcqLkm3/ppud3Z+FD4/Q=="
}
EOM
echo
rm ${CONF}

echo
echo "Starting random generation test."
CONF=$(mktemp)
mkconfig ${CONF} operator:OperatorOperator /v1/random
time ${CURL} --config ${CONF} 2>&1 >/dev/null <<EOM | fold -w 100
{
  "length": 1024
}
EOM
echo
rm ${CONF}
