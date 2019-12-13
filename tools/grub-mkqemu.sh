#!/bin/bash
#
# Create a minimal GRUB image suitable for booting from ROM in QEMU/KVM (via
# -kernel).
#
# The minimal set of modules for booting a Muen-based NitroHSM on QEMU/KVM with
# a q35 machine model is included. Note that due to the way GRUB works, the
# embedded CONFIG cannot contain any 'menuentry' directives, and the script
# parser is very limited (e.g. no 'if' command).

usage ()
{
    cat <<EOM 1>&2
Usage: $0 OUTPUT CONFIG

Creates a minimal GRUB image suitable for boothing from ROM in QEMU/KVM.
Image will be written to OUTPUT, and CONFIG will be embedded as the GRUB
early config file.
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

OUTPUT="$1"
CONFIG="$2"
MODULES="ahci part_gpt cpio multiboot"
ROOT="(ahci0,gpt1)"

(set -x; grub-mkimage -O i386-pc -c ${CONFIG} -p ${ROOT} -o ${OUTPUT} \
    ${MODULES}) \
    || die "Could not create '${OUTPUT}': grub-mkimage failed"
