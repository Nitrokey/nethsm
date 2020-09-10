#!/bin/bash
#
# Generate a new GPG signing key suitable for use with SBS and PGP verification
# by GRUB.
#
# KEYDIR must exist and be an empty directory, this is intentional.
# KEYDIR is laid out as follows:
#
# KEYDIR/private/
#     GPG home directory, private keys
# KEYDIR/key.pub
#     Exported public key
#

usage ()
{
    cat <<EOM 1>&2
Usage: $0 KEYDIR

Generate a new GPG signing key suitable for use with SBS and PGP verification
by GRUB.

KEYDIR must exist and be an empty directory, this is intentional.

A .gitignore file will be produced in KEYDIR to allow for easy "git add".
EOM
    exit 1
}

die ()
{
    echo $0: ERROR: "$@" 1>&2
    exit 1
}

if [ $# -ne 1 ]; then
    usage
fi

KEYDIR="$1"

if [ ! -d "${KEYDIR}" ]; then
    die "${KEYDIR}: must exist and be an empty directory"
fi
if [ -n "$(ls ${KEYDIR})" ]; then
    die "${KEYDIR}: must exist and be an empty directory"
fi

KEYCOMMENT="NitroHSM signing key ($(basename "${KEYDIR}"))"
GPGDIR="${KEYDIR}/private"
mkdir -p "${GPGDIR}" || die "Could not create ${GPGDIR}"

cat <<EOM >"${GPGDIR}/tmp-gen-key"
%no-protection
Key-Type: RSA
Key-Length: 4096
Key-Usage: sign
Expire-Date: 0
Name-Comment: ${KEYCOMMENT}
%commit
EOM

PUBKEY="${KEYDIR}/key.pub"

gpg --homedir "${GPGDIR}" --batch --generate-key "${GPGDIR}/tmp-gen-key" \
    || die "GPG failed while generating key"
gpg --homedir "${GPGDIR}" --batch --export >"${PUBKEY}" \
    || die "GPG failed while exporting public key"

cat <<EOM >"${KEYDIR}/.gitignore"
private/*~
private/trustdb.gpg
private/tmp-*
private/openpgp-revocs.d/
EOM

