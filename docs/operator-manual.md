% NetHSM Operator Manual

# Initial Installation on Hardware {#sec-iih}

To perform initial installation on a stock hardware unit, follow these steps:

1. Download the build you would like to install from the NetHSM builds [repository][builds].
2. Flash `coreboot.rom` from the build to the unit with an external programmer.
3. Attach the SSD to your machine, e.g. using an USB to SATA adapter, and note down the block device `/dev/sdX` of the SSD.
4. Ensure you have the following system packages installed:
    - `cgpt`
    - `e2fsprogs`
5. As root, run the installer [script][installer] using `/dev/sdX` and the `system.img.cpio` from the build.
6. Insert the SSD into the hardware unit, making sure that it is connected to the **first** SATA controller.

See [System Console](#sec-sc) for details on how to access the console of the unit.

[builds]: https://git.nitrokey.com/nitrokey/nethsm/ci-builds
[installer]: https://git.nitrokey.com/nitrokey/nethsm/nethsm/-/raw/master/tools/nethsm-install.sh

Alternatively, for development purposes, if you have a Debian 10 host system (**not a container**) available to build it with, you can also install the System Software by booting a signed "development" installer based on Debian Live from USB. See the [README.md][usbinstaller] for details.

[usbinstaller]: https://git.nitrokey.com/nitrokey/nethsm/nethsm/-/blob/master/src/installer/README.md

# System Software Update {#sec-update}

During the build process, the version number from the toplevel CHANGES.md file is used. The version number is MAJOR.MINOR. Downgrades are only allowed in the same MAJOR line.

For example to release a new version 42.5, add the following to the top of CHANGES.md: "# 42.5 (2022-02-27)"

Add the changes (as a markdown list) before the previous release marker. This will be taken as user-visible changes in the update image.

# System Software Update Signing {#sec-ssus}

A _System Software_ update image must be signed twice, once for the verified boot (the boot key signature), and once including the ChangeLog with the software update key. The public software update key is passed to the keyfender library during `Hsm.boot`. By default, the unikernel copies `src/keyfender/test/public.pem` (private part is `src/keyfender/test/key.pem`) to `src/s_keyfender/update_key_store/key.pem`, which is embedded into the unikernel at build time. It must be a PEM encoded RSA public key. By default, builds are all automatically signed with test keys. If the Makefile variable `UPDATE_KEY_SMARTCARD` is set, the public key is extracted from the Nitrokey to be embedded into the unikernel. In addition, the Nitrokey is used for signing the update image (using `bin/sign_update.exe`).

To add the boot key signature to a software update image the keyfender library provides `bin/sign-update.exe`. Please read the output of `sign-update.exe --help` for instructions how to use it. The output file can be uploaded to a NetHSM (/system/update endpoint). The signature is created by `openssl pkeyutl`.

## Using Nitrokey Pro For Image Signing

This guide uses a Nitrokey Pro 2 to store the signature keys. The Nitrokey is in factory default. It is recommended to set the user and admin PIN before using the Nitrokey in production. The software components required for this guide are OpenSC tools with pcscd daemon, GnuPG with scdaemon, and sbs_create supporting smartcards.

## Initial Key Creation

These instructions assume the current work directory is the NetHSM repository.

Before you start make sure that there are no running processes of GnuPG and pcscd. GnuPG processes can be terminated with the `gpgconf --kill all` command. The pcscd process usually runs as a daemon started by systemd. It can be terminated with `systemctl stop pcscd.socket pcscd.service`.

### Prepare GnuPG Environment

Create the directories `keys/smartcard` with `mkdir -p keys/smartcard`, and `keys/smartcard/private` with `mkdir -m 700 -p keys/smartcard/private`. The directory `smartcard` will contain a copy of the public key, and the directory `private` the GnuPG home.

### Create OpenPGP Key

Create the OpenPGP key, using the path `keys/smartcard/private` as GnuPG home directory, with `gpg --homedir keys/smartcard/private --expert --full-generate-key`.

In the menu we use the following values to create the key.
- Type of key: 4 (RSA sign only)
- Key size: 4096
- Key expiration (does not expire): 0
- Real name: Nitrokey NetHSM Signature
- Email address: info@nitrokey.com
- No Comment

The passphrase for the key must not be set yet because it would prevent the conversion to OpenSSL.

Set the environment variable with the ID of the generated key: `export KEYID=<key id>`

### Convert OpenPGP Key to OpenSSL Key

`gpg --homedir keys/smartcard/private --export-secret-key $KEYID | openpgp2ssh $KEYID | openssl pkey -outform DER -out private.der`

### Protect OpenPGP Key With Password

`gpg --homedir keys/smartcard/private --change-passphrase info@nitrokey.com`

### Backup OpenPGP Keys

Create a backup of the public and secret key.
The public key can be exported with `gpg --homedir keys/smartcard/private --export info@nitrokey.com > public.gpg`.
The secret key can be exported with `gpg --homedir keys/smartcard/private --export-secret-key info@nitrokey.com > private.pgp`.
The export operation of the secret key requires the passphrase set in the previous step.

The files `private.gpg` and `public.gpg` contain the private and public keys. Hence this files should not become part of the repository. Move this file to a different path outside of the NetHSM repository before continuing.

The file `private.der` is not password-protected, can be converted from OpenPGP at anytime, and therefore must not being backed up.

### Write OpenPGP Public Key to Smartcard Directory.

Write a copy of the public key to the `keys/smartcard` directory with `gpg --homedir keys/smartcard/private --export info@nitrokey.com > keys/smartcard/key.pub`.

### Write OpenPGP Key to Nitrokey

Connect the Nitrokey and make sure it is the only connected smartcard. Write the secret key to the Nitrokey with `gpg --homedir keys/smartcard/private --edit-key info@nitrokey.com`. In the following menu enter `keytocard`. Select to store the key in the signature key slot. The `keytocard` operation requires the passphrase set during key creation, and the admin PIN of the Nitrokey. Afterwards confirm the change with the `save` command. This will delete the secret key from the keyring and replace it with a stub key referring to the Nitrokey.

Eventually terminate all running GnuPG processes with `gpgconf --homedir keys/smartcard/private --kill all`.

### Write OpenSSL Key to Nitrokey

Connect the Nitrokey and make sure it is the only connected smartcard. Set the stored key type on the Nitrokey with `gpg --edit-card`. In the shell enter `admin` to enable the use of admin commands, and set the key type with `key-attr`. GnuPG will now ask for the key type to use. Change all to key type `RSA` with a key length of `4096`. Afterwards terminate the all GnuPG processes with `gpgconf --kill all`.
The following command needs a running pcscd daemon. Start it with `systemctl start pcscd.socket pcscd.service`.
Write the secret key to the Nitrokey with `pkcs11-tool -l --login-type so --id 03 --type privkey -w private.der`.
When the key was successfully written to the Nitrokey, the pcscd daemon can be terminated again with `systemctl stop pcscd.socket pcscd.service`.

### Delete Private Key Files

Safely delete `private.der`, `private.pgp` and `keys/smartcard/private/private-keys-v1.d/*` if not done previously.

### Commit Changes to Repository

Finally the files `keys/smartcard/key.pub` and `keys/smartcard/private/pubring.kbx` must be committed to the repository. Add them to staging with `git add keys/smartcard/key.pub keys/smartcard/private/pubring.kbx`, and commit with `git commit`.

## Signing With Build Container

The following instructions assume the current work directory is the cloned NetHSM repository.

1. Make sure there are no processes of GnuPG and pcscd running on the host. GnuPG processes can be terminated with `gpgconf --kill all`, and pcscd with `systemctl stop pcscd.socket pcscd.service`.
2. Connect the Nitrokey with the computer. Make sure no other smartcard is connected.
3. Check for the USB bus and device IDs of the Nitrokey with `lsusb | grep Nitrokey`. The bus and device IDs will in the following result into the paths `/dev/bus/usb/<bus-id>/<device-id>` for the device node.
4. Make sure the device node is writable by giving them the write permission `sudo chmod o+w /dev/bus/usb/<bus-id>/<device-id>`.
5. Login to the Docker registry with `docker login registry.git.nitrokey.com`.
6. Pull the builder container with `docker pull registry.git.nitrokey.com/nitrokey/nethsm/nethsm/builder`.
7. Prepare the download cache with `mkdir -p downloads/opam`.
8. Run the container with `docker run --rm -ti -v $PWD:/src -v $PWD/downloads:/downloads --device /dev/bus/usb/<bus-id>/<device-id> -e MODE=muen -e MUEN_HARDWARE=prodrive-hermes-1.0 -e BUILD_CACHE_DIR=/downloads registry.git.nitrokey.com/nitrokey/nethsm/nethsm/builder /bin/bash`. Make sure to replace the `/dev/bus/usb/<bus-id>/<device-id>` the paths to the USB device node with the values from step 3 above.
9. Inside the container run `rm -rf ~/.opam/download-cache && ln -s /downloads/opam ~/.opam/download-cache && git clone /src . && mkdir ~/.ssh && ssh-keyscan git.nitrokey.com > ~/.ssh/known_hosts`.
10. Make sure to have a SSH secret key in `~/.ssh/id_rsa` with access to `git.nitrokey.com`. Change the permissions on this one with `chmod 600 ~/.ssh/id_rsa`.
11. Make sure to build the shadowed private key cache in the `keys/smartcard/private/private-keys-v1.d/` directory by running `gpg --homedir keys/smartcard/private --card-status`. Afterwards run `gpgconf --homedir keys/smartcard/private--kill all` to end all GnuPG processes.
12. In the `Makefile.sub` set the variables `BOOT_KEY_SMARTCARD` and  `UPDATE_KEY_SMARTCARD` to `1`, i.e. `UPDATE_KEY_SMARTCARD ?= 1`, to enable the build with signing keys from the Nitrokey. Set the PIN in `UPDATE_KEY_SMARTCARD_USER_PIN` accordingly.
13. Start the build with `make OPAMJOBS=$(nproc) -j$(nproc) artifacts`.

# Reset to Factory Defaults {#sec-rtfd}

Until this feature is implemented, you can use the following method to reset a unit to factory defaults if the unlock passphrase is lost:

Disassemble hardware, attach SSD to a computer. Wipe the data partition (assuming "sdb" is the disk):

    | mkdir -p /tmp/empty /tmp/data/git
    | git init --bare --template=/tmp/empty /tmp/data/git/keyfender-data.git
    | MKE2FS_CONFIG=src/u-root/etc/mke2fs.conf mke2fs -t ext4 -E discard -F -m0 -L data -d /tmp/data /dev/sdb3
