% NetHSM Operator Manual

# Introduction {#sec-i}

**TODO**: Complete this section, and/or re-structure this document better, at the moment it's a "grab-bag" of various things.

# Initial Installation on Hardware {#sec-iih}

**TODO**: The final structure of the NetHSM builds [repository][builds] has not yet been decided upon, and this process will also change once signing of images with production keys via an external USB Smartcard is implemented. Current builds are all automatically signed with test keys.

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

To release a new version 42.5, add the following to the top of CHANGES.md: "# 42.5 (2022-02-27)"

Add the changes (as a markdown list) before the previous release marker. This will be taken as user-visible changes in the update image.

# System Software Update Signing {#sec-ssus}

A _System Software_ update image must be signed twice, once for the verified boot (the inner signature), and once including the ChangeLog with the software update key. The public software update key is passed to the keyfender library during `Hsm.boot`. By default, the unikernel copies `src/keyfender/test/public.pem` (private part is `src/keyfender/test/key.pem`) to `src/s_keyfender/update_key_store/key.pem`, which is embedded into the unikernel at build time. It must be a PEM encoded RSA public key. If the Makefile variable `OUTER_SMARTCARD` is set (to a PKCS11 URL), the public key is extracted from the SmartCard to be embedded into the unikernel. In addition, the SmartCard is used for signing the update image (using `bin/sign_update.exe`).

To add the outer signature to a software update image the keyfender library provides `bin/sign-update.exe`. Please read the output of `sign-update.exe --help` for instructions how to use it. The output file can be uploaded to a NetHSM (/system/update endpoint). The signature is created by `openssl pkeyutl`.

## Using a Nitrokey Pro for signing the image

The steps to store the private key(s) on a Nitrokey Pro are (using OpenSC at 0.23.0, ccid 1.5.0, Nitrokey Pro 3.4)
- Generate a RSA key: `pkcs11-tool -l --login-type so --so-pin 12345678 --keypairgen --key-type rsa:2048 --label outer` (somehow the label gets overwritten anyways, the provided ID is as well not the one used in the Nitrokey)
- Use `pkcs11-tool -O` to dump the slot ID (in our case 03)
- Set the Makefile variables OUTER_SMARTCARD to yes, OUTER_SMARTCARD_SLOT to the slot (03), and OUTER_SMARTCARD_USER_PIN in the Makefile.sub (or via environment)

TODO: still needs the OpenPGP on the SmartCard

# Rate Limiting {#sec-rl}

To limit brute-forcing of passphrases, **S-Keyfender** rate limits logins. The rate for the unlock passphrase is one failed access per second per IP address. The rate limit for all endpoints requiring authentication is 1 failed authentication per second per IP address and username.

# Reset to Factory Defaults {#sec-rtfd}

Until this feature is implemented, you can use the following method to reset a unit to factory defaults if the unlock passphrase is lost:

Disassemble hardware, attach SSD to a computer. Wipe the data partition (assuming "sdb" is the disk):

    | mkdir -p /tmp/empty /tmp/data/git
    | git init --bare --template=/tmp/empty /tmp/data/git/keyfender-data.git
    | MKE2FS_CONFIG=src/u-root/etc/mke2fs.conf mke2fs -t ext4 -E discard -F -m0 -L data -d /tmp/data /dev/sdb3

# System Console {#sec-sc}

Debug output is written to the serial console (multiplexed from the different subjects by Muen). To gather debug information, hook up a serial cable (115200, 8N1) to COM1 on the unit.

# Cryptographic Parameters {#sec-cp}

The key generated for the HTTPS endpoint is an EC key (P256).

The keyfender library includes some choices of cryptographic parameters, in keyfender/crypto.ml.
- SCRYPT-KDF: b=16384, r=8, p=1, salt length 16 byte.

The data stored on disk is encrypted with AES256-GCM (32 byte key, nonce size is 12, based on [stackexchange] this should be fine).

[stackexchange]: https://crypto.stackexchange.com/questions/5807/aes-gcm-and-its-iv-nonce-value

# Known Issues {#sec-ki}

Apart from the features mentioned as not yet implemented in the System Design document, the following known issues exist:

- If the **S-Keyfender** subject runs out of memory, it exits (logging on serial console), and the unit needs to be cold booted (hard reset).
