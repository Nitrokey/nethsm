# Provision a key for signing software updates

A software update image must be signed twice, once for the verified boot (the inner signature), and once including the ChangeLog with the software update key. The public software update key is named "update.pem", and located in src/keyfender of this repository. It must be a PEM encoded RSA public key.

To add the outer signature to a software update image the keyfender library provides "bin/sign-update.exe". Please read the output of "sign-update.exe --help" for instructions how to use it. The output file can be uploaded to a NitroHSM (/system/update endpoint).

# First installion on hardware

# Rate limiting

To limit brute-forcing of passphrases, **S-Keyfender** rate limits logins. The rate for the unlock passphrase is enforced globally (at the moment at most 10 accesses per second). The rate limit for all endpoints requiring authentication is 10 per second per IP address.

# Reset to factory defaults (when unlock passphrase is lost)

Disassemble hardware, attach SSD to a computer. Wipe the data partition (assuming "sdb" is the disk):

    | mkdir -p /tmp/empty /tmp/data/git
    | git init --bare --template=/tmp/empty /tmp/data/git/keyfender-data.git
    | mke2fs -t ext4 -E discard -F -m0 -L data -d /tmp/data /dev/sdb2

# Reading output from serial console

Debug output is written to the serial console (multiplexed from the different subjects by Muen). To gather debug information, hook up a serial cable (115200, 8N1).

# Cryptographic parameters

The keyfender library includes some choices of cryptographic parameters, in keyfender/crypto.ml. These should be adjusted before deployment:
- RSA key size (for the TLS endpoint): 1024 (should be at least 2048)
- PBKDF iterations: 1000 (should be at least 100_000), salt length 16 byte.

The data stored on disk is encrypted with AES256-GCM (32 byte key, nonce size is 12, based on [stackexchange] this should be fine).

[stackexchange]: https://crypto.stackexchange.com/questions/5807/aes-gcm-and-its-iv-nonce-value

# Current limitations

Some features mentioned in the system design are not yet implemented:
- Full disaggregation of the Muen subjects (currently, S-Platform and S-Update are combined in a single S-Kitchen-Sink).
- Software update functionality is not yet implemented.
- S-TRNG is not implemented.
- A physical reset is not implemented.
- If the S-Keyfender subject runs out of memory, it exits (logging on serial console), and needs to be cold bootet.
