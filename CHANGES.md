# 3.1 (2025-10-13)

* Revert back to old PKCS1 signing format
* Reduce ARP cache timeout from 20 to 1 minute

# 3.0 (2025-09-30)

* Support for SECP256K1 curve and BIP-340 signatures
* Support for Brainpool-P256/P384/P512 curves
* Substantial crypto performance improvements
* Improved performance of restore operation
* Improved security of ECDSA with random k
* Allow KeyIDs and UserIDs to include characters -_.
* Allow setting of subjectAltNames in CSRs
* Allow shutdown in Locked or Unprovisioned state
* Allow restore without BackupPassphrase if possible
* New API for moving keys
* New API for listing a range of keys
* Fix initial gratuitous ARP request
* Fix deleting tags for keys in a namespace
* Add DigestInfo in RSA PKCS1 signing
* Remove support for NIST-P224 curve (upstream change)
* Internal: Upgrade to MirageOS 4.9

# 2.2 (2025-05-07)

* Fix of invalid TPM DA protection in NetHSM 2
* Fix of CSR format

# 2.1 (2025-01-12)

* Keep real MAC address of ethernet device
* Support for new NetHSM 2 hardware (MSI Z790)
* Upgrade to Muen 1.1.1

# 2.0 (2024-08-01)

* Implementation of namespaces
* Substantial crypto performance improvements
* Improved performance of restore and update operations
* Fix of memory leak during backup
* Fix of restore in operational state

# 1.0 (2023-11-27)

* Initial release

# 0.10

* Release candidate for 1.0

# 0.9

* Alpha version
* Don't use for production

# 0.1 (2019-09-16)

* Initial development
