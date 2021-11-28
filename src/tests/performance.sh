#!/usr/bin/env bash

set -x

source "$(dirname $0)/common_functions.sh"

JOBS="${JOBS:-4}"
ITERS="${ITERS:-400}"
PARALLEL="parallel --halt now,fail=1 -n0 -j${JOBS}"

rsa2048_gen () {
    echo "RSA 2048 bit key generation with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_admin /v1/keys/generate <<EOM
{ "mechanisms": ["RSA_Signature_PKCS1", "RSA_Decryption_PKCS1"], "type": "RSA", "length": 2048 }
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

rsa4096_gen () {
    echo "RSA 4096 bit key generation with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_admin /v1/keys/generate <<EOM
{ "mechanisms": ["RSA_Signature_PKCS1", "RSA_Decryption_PKCS1"], "type": "RSA", "length": 4096 }
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

p256_gen () {
    echo "P256 key generation with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_admin /v1/keys/generate <<EOM
{ "mechanisms": ["ECDSA_Signature"], "type": "EC_P256"}
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

rsa2048_sign () {
    echo "RSA 2048 bit PKCS1 signing with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/rsa2048/sign <<EOM
{
  mode: "PKCS1",
  message: "SGkgQWxpY2UhIFBsZWFzZSBicmluZyBtYWxhY3DDtnJrw7ZsdCBmb3IgZGlubmVyIQo="
}
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

rsa4096_sign () {
    echo "RSA 4096 bit PKCS1 signing with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/rsa4096/sign <<EOM
{
  mode: "PKCS1",
  message: "SGkgQWxpY2UhIFBsZWFzZSBicmluZyBtYWxhY3DDtnJrw7ZsdCBmb3IgZGlubmVyIQo="
}
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

p256_sign () {
    echo "P256 signing with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/p256/sign <<EOM
{
  mode: "ECDSA",
  message: "LCa0a2j/xo/5m0U8HTBBNBNCLXBkg7+g+YpeiGJm564="
}
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

rsa2048_decrypt () {
    echo "RSA 2048 bit PKCS1 decryption with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/rsa2048/decrypt <<EOM
{
  mode: "PKCS1",
  encrypted: "ADLOB8thK6ZkeJByjG9u5kakO9dU/msVXPo1DvPkv0xp88AZq3hMx/YUctiniVprPdq7AaHNbXlbL2LSO61r0H1nnp7iqtORDFr1CiTmwol1NKz/q6RxjbWBAj5uVG7l59Dfq/AwqF7gzha36w4mt2Smh9Y0mY+q0Wl7oy87bPCqcj3QFFXyZ1poeFiUDxNgoKUV7CpmhtxGU9OYHhxvQKVq97/dnRiX07FoHr/90csVUWM0JtC2snVuCzfYnl4bbeWHG731rJ8XSoTj1dF0+lY+Qegrup8tSkVm52YQaDMXIeI8gO/zrnVmAettKGbLprmcqLkm3/ppud3Z+FD4/Q=="
}
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

rsa4096_decrypt () {
    echo "RSA 4096 bit PKCS1 decryption with $JOBS parallel jobs and $ITERS iterations."
    REQUEST=$(mktemp)
    cat <<EOF >${REQUEST}
source "$(dirname $0)/common_functions.sh"
POST_operator /v1/keys/rsa4096/decrypt <<EOM
{
  mode: "PKCS1",
  encrypted: "jPsCDxIJtkzqmgy8VKSGERel4ZoBZBr7RG9uALEkm5anMfHcWtYy5plHyNaVKDFN2oeBUADZtmGskKuaf4S03yym4ZB5Eur2WMpyTbGN1E6Lf0pIbzHe11cZyCZ202MI6qnv5oxl3jZxn+wbLeRAma6w9E9FjVD6XlkTvZLm6CCvSU/QbUh6IxgSlSsDGFW56Ri7VGHcsYdjJQMLPZ3RUETmS2E8++PgdO8nxoRrd7wMdW371vJLkO69SRwump9kx5/Ktt+oJbkhPk3YMsRPbDInKglu6/TE/4D3PGOS40Gu94eoacuSJ6OAxkwFHT1mRd+n5ucL26WDRuhFfnfcnuvTYTzaX4EmLCuRaoWObjIRowfyNUqr/T3L8PwreMPgVaf5zVI/9DNvK+uY78yr47aN1m7Cqh/cks3HfL0l48VFzIeV7Ixwsv2oIvL8QGEZflOwkekG24Skb1pep2XHMQkue5araLkclYUHnsw5ygSk78vboSoQhs7VodjGxNyGTWBjXh76BFLYRUERyUc1uqUwGwKV0ApHTL7Vr8vDORrsoNtcpiJJZFTRuMqb9qCpeV8KcFsPHQLlPRZBWcGcpxreSZfTQn7h5GO6M5zjI1Y1mFIp2YWjrFPSoQvnrx/bk/Bvgah1lLzVFDo8Ke5sMMnQH6lwQ+QPli+aJdJCNLQ="
}
EOM
EOF
    seq ${ITERS} | ${PARALLEL} bash ${REQUEST} || exit 1
    rm ${REQUEST}
}

provision () {
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

    # create operator
    PUT_admin /v1/users/operator <<EOM
{
  realName : "operator",
  role: "Operator",
  passphrase: "OperatorOperator"
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
    echo "Setup complete."
}

add_rsa2048 () {
    echo "Adding rsa2048 key."
    # put a RSA 2048 bit key
    PUT_admin /v1/keys/rsa2048 <<EOM
{
  mechanisms: ["RSA_Decryption_PKCS1", "RSA_Signature_PKCS1"],
  type: "RSA",
  key: {
    primeP: "APWssfg0uM2HevzjbDM+Om8ThaGLNoxzJkujtbT55SPhx5ntnDiktTXNRAHdwJgAc1HPVVCm6nESSIZ0ZqO+rh2vRYT+oXMHre0zhpGDZMVAB31zowTUv+6d7lakMbqN3hDjpxaiP3Xg7my4qMCrnnFyBq7LuE/0zw2SeoQnKlY1",
    primeQ : "ANAc/C1uKDdSsgc/du5N4B8vLZH8aC+poVyq8eZwkgs71vG3XccW6gEkC5dh439DKdZKYj3pywq39NNjzAK0VSs9TnscttaVtaS45rctpyP5nNoQnsVe3euc55P9UKuV9tRw7nnSi0Tf1QDbphEP/bsXj7F4FG6McdheXLPzV7M7",
    publicExponent : "AQAB"
  }
}
EOM
    echo "Completed."
}

add_rsa4096 () {
    echo "Adding rsa4096 key."
    # put a RSA 4096 bit key
    PUT_admin /v1/keys/rsa4096 <<EOM
{
  mechanisms: ["RSA_Decryption_PKCS1", "RSA_Signature_PKCS1"],
  type: "RSA",
  key: {
    primeP: "APiF89+5Bpxxsl93H2pG9lSFq5cea5y8xIM6NMsOihisG55qCsTRaHQPvxPzKtjciJg6x1/jCH8lns44eaE99qR1N78hZqSETHNCJKEzTRzsAwrRoFJhVzvw5VgFqWtJOiB7djvE9FTjv68HGlPJysIQxw1UI4PVLWLHsxpSs4jmp4Uy48sS3wP+C1/Spf7gB6x1vNrLHVm2pXo0gavNWmsBBCdOufQHP9+a9V7CRwJEd0udfEnMtToB3wg+ER9mnUV26jr4lHrjXgm/6qQaFn2Vk5TTRfx6RSSId5sE0ur7wav/9mReFj2N7FTd+7ulb3rnaKH4ZpI5sZOyrWer1G8=",
    primeQ : "AM5QN5bS/2s10eAQ1MlE7RBYWCMtb8OFc+m+YqGA4vMSAE9rdvYxjJWFK3hoVHoHfEVmxIArz4SE9yA8FtTnQmEhXHJZkVCsUFaP/LTKtsMSef9O1KusgOBh7ro8VQlU8pOJDg85AvuBfNAcGY81QUXfnKpRGh9DTQisq5fYDUY9y51ou/oQShtO399AAOF/+1x+gwiTPLYx2hTKb9astWObn1TfkqM/gISLSN7p1RPUyVoJ7UycpX+ZUXx/z9tAKOCEHK9gDQqaT1cnnBYF1LOHvMaDrIJ8pA+5J4C2M0mmOvtZ6zy+OtngNfEM5Xg4LDhgKwZhza1vy/DM1bkjRe0=",
    publicExponent : "AQAB"
  }
}
EOM
    echo "Completed."
}

add_p256 () {
    echo "Adding p256 key."
    # put a P256 bit key
    PUT_admin /v1/keys/p256 <<EOM
{
  mechanisms: ["ECDSA_Signature"],
  type: "EC_P256",
  key: {
    data: "n0HHZm8rFRY0XO4FpS42azls3qgQ75o/m2m2H6VQGSQ="
  }
}
EOM
    echo "Completed."
}

case "$1" in
    rsa2048_gen) provision ; rsa2048_gen;;
    rsa4096_gen) provision ; rsa4096_gen;;
    p256_gen) provision ; p256_gen;;
    rsa2048_sign) provision ; add_rsa2048 ; rsa2048_sign;;
    rsa4096_sign) provision ; add_rsa4096 ; rsa4096_sign;;
    p256_sign) provision ; add_p256 ; p256_sign;;
    rsa2048_decrypt) provision ; add_rsa2048 ; rsa2048_decrypt;;
    rsa4096_decrypt) provision ; add_rsa4096 ; rsa4096_decrypt;;
    *) echo "unsupported load test"
esac
