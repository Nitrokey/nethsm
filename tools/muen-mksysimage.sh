#!/bin/bash
#
# Create a Muen system image in CPIO format, suitable for dumping to a system
# partition.
#
# The CSL/SBS image will be signed with the keys in KEYDIR.

TMPDIR=
cleanup ()
{
    if [ -n "${TMPDIR}" ]; then
        if [ -d "${TMPDIR}" ]; then
            rm -f ${TMPDIR}/grub.cfg ${TMPDIR}/grub.cfg.sig ${TMPDIR}/muen.img
            rmdir ${TMPDIR}
        fi
    fi
}

usage ()
{
    cat <<EOM 1>&2
Usage: $0 KEYDIR OUTPUT MUEN_IMAGE_CSL

Create a Muen system image in CPIO format as OUTPUT, suitable for dumping to a
system partition.

The CSL/SBS image will be signed with the keys in KEYDIR.
EOM
    exit 1
}

die ()
{
    echo $0: ERROR: "$@" 1>&2
    cleanup
    exit 1
}

if [ $# -ne 3 ]; then
    usage
fi

KEYDIR="$1"
OUTPUT="$2"
MUEN_IMAGE_CSL="$3"

GPG_SIGN="$(dirname $0)/gpg-sign-detached.sh"
SBS_CREATE="/nethsm-tools/muen/tools/sbs/bin/sbs_create"

# Create Muen system image
TMPDIR=$(mktemp -d)
# We need to provide a signed grub.cfg for the firmware to chain into.
cat <<EOM >${TMPDIR}/grub.cfg
csl /muen.img
boot
EOM
${GPG_SIGN} ${KEYDIR} ${TMPDIR}/grub.cfg \
    || die "While signing GRUB configuration: failed"
${SBS_CREATE} -k ${KEYDIR}/private -i ${MUEN_IMAGE_CSL} -o ${TMPDIR}/muen.img \
    || die "While creating SBS image: sbs_create failed"

(set -x; echo -e grub.cfg\\ngrub.cfg.sig\\nmuen.img | \
    cpio -R +0:+0 --reproducible -D "${TMPDIR}" -o >${OUTPUT}) \
    || die "While creating system: cpio failed"

cleanup

