#!/bin/bash
#
# This is the installer script for NetHSM.
#
# Requirements: cgpt, mke2fs, standard Linux utilities.
#
# This script serves three purposes:
#
# 1. As an "offline" installer, intended to be run on a system with a disk
#    attached to which the NetHSM System Software should be installed.
# 2. As an "online" installer, included on the live USB installer system.
# 3. For creating a disk image when building the Muen system for QEMU/KVM.
#

usage ()
{
    cat <<EOM 1>&2
Usage: $0 [ -f ] [ -E SIZE ] DISK SYSTEM_IMAGE

NetHSM installer script.

Formats the block device at DISK and installs the NetHSM image at
SYSTEM_IMAGE to it. SYSTEM_IMAGE should be the binary contents of
the 'system' partition, normally obj/disk.image.cpio from the build
process.

If the -f option is specified then interactive confirmation prompts
will be skipped; use at your own risk.

If the -E option is specified then rather than using a block device,
a disk image of SIZE will be created at the path DISK; this is intended
for use when building a disk image for QEMU/KVM.
EOM
    exit 1
}

die ()
{
    echo $0: ERROR: "$@" 1>&2
    exit 1
}

askyn ()
{
    if [ $# -ne 0 ]; then
        prompt="$@ [y/N] "
    else
        prompt="Do you wish to proceed? [y/N] "
    fi

    echo -n "${prompt}"
    read line
    case "${line}" in
        y*|Y*)
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

sepa ()
{
    echo "--------------------------------------------------------------------------------"
}

opt_FORCE=
opt_EMULATE=
while getopts "fE:" opt; do
    case "${opt}" in
        f)
            opt_FORCE=1
            ;;
        E)
            opt_EMULATE=1
            emulate_SIZE="${OPTARG}"
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))

[ $# -ne 2 ] && usage

is_interactive ()
{
    [ -z "${opt_FORCE}" ]
}

is_emulated ()
{
    [ -n "${opt_EMULATE}" ]
}

REL_PATH=$(dirname ${BASH_SOURCE})
MKE2FS_CONF=${REL_PATH}/../src/u-root/etc/mke2fs.conf

if [ ! -r "${MKE2FS_CONF}" ]; then
	  die "Did not find custom ${MKE2FS_CONF} ... aborting install!"
fi


DISK="$1"
MUEN="$2"
if is_emulated; then
    if is_interactive; then
        [ -f "${DISK}" ] && die "Will not overwrite existing file: ${DISK}"
    fi
else
    [ -b "${DISK}" ] || die "Not a block device: ${DISK}"
    [ $(id -u) -ne 0 ] && die "Must be run as root user"
fi
[ -f "${MUEN}" ] || die "Not found: ${MUEN}"

if ! is_emulated; then
    DEVINFO=$(lsblk -o NAME,HCTL,VENDOR,MODEL,REV,TRAN,SIZE,STATE "${DISK}")
    [ $? -ne 0 ] && die "Could not retrieve block device information"
else
    truncate -s "${emulate_SIZE}" "${DISK}" \
        || die "Could not create disk image: ${DISK}"
    DEVINFO=$(ls -l "${DISK}")
fi

MUENINFO=$(ls -l "${MUEN}")
[ $? -ne 0 ] && die "Could not retireve System Image information"

if is_interactive; then
    cat <<EOM

You are about to install NetHSM from:

${MUENINFO}

on the block device ${DISK}:

${DEVINFO}

ALL DATA ON THE BLOCK DEVICE WILL BE DELETED.

EOM

    askyn || die "Aborted"
    sepa
fi

# Create GPT partition table.
disk_size=$(blockdev --getsz ${DISK})
p1_start=128
# p1 System partition size in 512-byte sectors.
p1_size=524288
p2_start=$((${p1_start} + ${p1_size}))
# p2 Backup system partition size in 512-byte sectors.
# (currently unused)
p2_size=524288
p3_start=$((${p2_start} + ${p2_size}))
# p3 Data partition is allocated all remaining space.
p3_size=$((${disk_size} - ${p3_start} - 33))
(set -x; cgpt create ${DISK}) \
    || die "While creating GPT: cgpt failed"
(set -x; cgpt add -b ${p1_start} -s ${p1_size} -t kernel -l system1 ${DISK}) \
    || die "While creating parition 1: cgpt failed"
(set -x; cgpt add -b ${p2_start} -s ${p2_size} -t kernel -l system2 ${DISK}) \
    || die "While creating parition 2: cgpt failed"
(set -x; cgpt add -b ${p3_start} -s ${p3_size} -t data -l data ${DISK}) \
    || die "While creating parition 3: cgpt failed"
(set -x; cgpt boot -p ${DISK}) \
    || die "While creating PMBR: cgpt failed"

if ! is_emulated; then
    # Force the kernel to re-read the partition table on the drive.
    # XXX: This behaves very non-deterministically. Perhaps ditch the use of
    # XXX: the partition block devices and use direct offsets as for QEMU?
    (set -x; blockdev --rereadpt ${DISK} && sleep 1) \
        || die "Failed to re-read partition table"
    # Double-check that the partition devices have actually shown up.
    [ -b "${DISK}1" ] || die "Partition not present: ${DISK}1"
    [ -b "${DISK}2" ] || die "Partition not present: ${DISK}2"
    [ -b "${DISK}3" ] || die "Partition not present: ${DISK}3"
fi

# Dump the Muen image to the system partition.
if is_emulated; then
    (set -x; dd if=${MUEN} of=${DISK} \
        obs=512 seek=${p1_start} conv=notrunc) \
        || die "While splicing system: dd failed"
else
    (set -x; dd if=${MUEN} of=${DISK}1 bs=1M) \
        || die "While installing image: dd failed"
fi

# Create an empty ext4 filesystem in the data parition.
if is_emulated; then
    fs_offset=$((${p3_start} * 512))
    # Size in megabytes, rounded down.
    fs_size=$((${p3_size} / 2048))
    (set -x; MKE2FS_CONFIG=${MKE2FS_CONF} mke2fs -t ext4 -F -m0 -L data -E discard,offset=${fs_offset} \
        ${DISK} ${fs_size}m) \
        || die "While creating data filesystem: mke2fs failed"
else
    (set -x; MKE2FS_CONFIG=${MKE2FS_CONF} mke2fs -t ext4 -E discard -F -m0 -L data ${DISK}3) \
        || die "While creating data filesystem: mke2fs failed"
fi

# Clean up.
sync

if is_interactive; then
    sepa
    echo "Success."
fi

