#!/bin/bash -ex

sudo chmod 777 /downloads
mkdir -p /downloads/opam
mkdir -p /downloads/ccache
ln -s /downloads/opam ~/.opam/download-cache
cp -a /src/. .
gpg --homedir keys/smartcard/private --card-status
gpgconf --homedir keys/smartcard/private --kill all
export UPDATE_KEY_SMARTCARD=1
export BOOT_KEY_SMARTCARD=1
export UPDATE_KEY_SMARTCARD_USER_PIN
read -s -p "PIN: " UPDATE_KEY_SMARTCARD_USER_PIN; echo
make OPAMJOBS=$(nproc) -j$(nproc) artifacts USE_CCACHE=1
cp -a obj/artifacts /src/artifacts-$(date +%s)
