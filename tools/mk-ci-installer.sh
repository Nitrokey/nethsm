#!/bin/sh -ex
#
# patch the installer image with a grub config for the CI
#

INSTALLER=$1
CI_INSTALLER=$2

CI_INSTALLER_GRUB_CFG=${PWD}/src/installer/grub-ci-installer.cfg
KEY_DIR=${PWD}/keys/test-key
SIGN=${PWD}/tools/gpg-sign-detached.sh

TMPDIR=$(mktemp -d)
cd ${TMPDIR}
cpio -ivd -F ${INSTALLER}
cp ${CI_INSTALLER_GRUB_CFG} boot/grub/grub.cfg
rm boot/grub/grub.cfg.sig
${SIGN} ${KEY_DIR} ${TMPDIR}/boot/grub/grub.cfg
find . -type f | cpio -v -o -H newc -F ${CI_INSTALLER}
rm -rf ${TMPDIR}
