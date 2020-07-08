#!/bin/bash
#
# Create a full disk image of a Muen-based NitroHSM system suitable for booting
# using GRUB under QEMU/KVM.
#
# Requirements:
#     - cgpt (from Chromium OS)
#     - mkfs.ext4
#
# TODO:
# Image size is currently hard-coded to 1GB, with a 512MB data partition.
# Populate the data partition with a bare Git repository.
# Support for updating an existing disk image with a new Muen system.

TMPDIR=
cleanup ()
{
    if [ -n "${TMPDIR}" ]; then
        if [ -d "${TMPDIR}" ]; then
            rm -f ${TMPDIR}/grub.cfg ${TMPDIR}/muen.img
            rmdir ${TMPDIR}
        fi
    fi
}

usage ()
{
    cat <<EOM 1>&2
Usage: $0 OUTPUT MUEN_IMAGE [POPULATE_DIR]

Creates a full disk image of a Muen-based NitroHSM system.
Disk image is output to OUTPUT. MUEN_IMAGE is the packed Muen system image
to use. If POPULATE_DIR is specified, the data partition will be pre-populated
with its contents.
EOM
    exit 1
}

die ()
{
    echo $0: ERROR: "$@" 1>&2
    cleanup
    exit 1
}

if [ $# -lt 2 ]; then
    usage
fi

DISK="$1"
MUEN="$2"
if [ -n "$3" ]; then
    POPULATE="-d $3"
else
    POPULATE=
fi

# Create empty disk image.
(set -x; dd if=/dev/zero of=${DISK} bs=1M count=1024) \
    || die "Could not create '${DISK}': dd failed"

# Create GPT partition table.
p1_start=128
p1_size=262144
p2_start=$((${p1_start} + ${p1_size}))
p2_size=1048576
(set -x; cgpt create ${DISK}) \
    || die "While creating GPT: cgpt failed"
(set -x; cgpt add -b ${p1_start} -s ${p1_size} -t kernel -l system ${DISK}) \
    || die "While creating parition 1: cgpt failed"
(set -x; cgpt add -b ${p2_start} -s ${p2_size} -t data -l data ${DISK}) \
    || die "While creating parition 2: cgpt failed"
(set -x; cgpt boot -p ${DISK}) \
    || die "While creating PMBR: cgpt failed"

# Splice Muen image into system partition, wrapped as a CPIO image.
TMPDIR=$(mktemp -d)
# We need to provide a grub.cfg for the firmware to chain into.
cat <<EOM >${TMPDIR}/grub.cfg
multiboot /muen.img
boot
EOM
cp ${MUEN} ${TMPDIR}/muen.img || die "While creating system: cp failed"
(set -x; echo -e grub.cfg\\nmuen.img | \
    cpio -R +0:+0 --reproducible -D "${TMPDIR}" -o >${DISK}.system.cpio) \
    || die "While creating system: cpio failed"

(set -x; dd if=${DISK}.system.cpio of=${DISK} \
    obs=512 seek=${p1_start} conv=notrunc) \
    || die "While splicing system: dd failed"

# Create an empty ext4 filesystem in the data parition.
fs_offset=$((${p2_start} * 512))
fs_size=$((${p2_size} / 2048))
(set -x; mkfs.ext4 -F -m0 -L data -E offset=${fs_offset} \
    ${POPULATE} ${DISK} ${fs_size}m) \
    || die "While creating data filesystem: mkfs.ext4 failed"

cleanup

