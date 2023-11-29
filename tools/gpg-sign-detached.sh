#!/bin/bash
#
# Create a detached GPG signature of INPUT using key from KEYDIR. Signature is
# output to <INPUT>.sig.
#

usage ()
{
    cat <<EOM 1>&2
Usage: $0 KEYDIR INPUT

Create a detached GPG signature of INPUT using key from KEYDIR. Signature is
output to <INPUT>.sig.
EOM
    exit 1
}

die ()
{
    echo $0: ERROR: "$@" 1>&2
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

KEYDIR="$1"
INPUT="$2"

if [ ! -d "${KEYDIR}" ]; then
    die "${KEYDIR}: does not exist"
fi

GPGDIR="${KEYDIR}/private"
if [ ! -d "${GPGDIR}" ]; then
    die "${GPGDIR}: does not exist"
fi

gpg --homedir "${GPGDIR}" --batch \
    --digest-algo SHA512 -b \
    -o "${INPUT}.sig" "${INPUT}" \
    || die "GPG failed while signing"

