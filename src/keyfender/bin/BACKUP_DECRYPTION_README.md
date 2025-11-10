# NetHSM Backup Decryption Tool

This directory contains a tool for fully decrypting NetHSM backup files exported as JSON.

## Overview

NetHSM backups use a multi-layer encryption scheme:

1. **Backup Passphrase Layer** (outermost): Encrypts the entire backup with AES-256-GCM using a key derived from the backup passphrase via scrypt
2. **Domain Key Layer**: The domain key itself is encrypted with the unlock passphrase
3. **Store-specific Encryption** (innermost): Keys in `/authentication/`, `/key/`, and `/namespace/` stores are encrypted with keys derived from the domain key using SHA-256
4. **Private Key Protection**: Extracted private keys from `/key/` are encrypted with age (either passphrase or recipient-based)

## Quick Start

```bash
# One-time setup: Create virtual environment with dependencies
./setup_venv.sh

# Step 1: Export backup to JSON
python3 export_backup.py MyBackupPassphrase backup.bin --output exported.json

# Step 2: Fully decrypt all values (with age passphrase encryption)
python3 decrypt_backup.py exported.json -o decrypted_backup/ --passphrase
# (will prompt for unlock passphrase, then age passphrase twice)

# OR use age recipient encryption
python3 decrypt_backup.py exported.json -o decrypted_backup/ --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# (will prompt for unlock passphrase only)

# OR use SSH recipient encryption
python3 decrypt_backup.py exported.json -o decrypted_backup/ --recipient "ssh-ed25519 AAAAC3Nza..."
# (will prompt for unlock passphrase only)
```

**Output**: Directory structure with all decrypted files:
```
decrypted_backup/
├── DECRYPTION_SUMMARY.json        # Summary of decryption process
├── initialized                    # Empty marker file
├── authentication/
│   ├── version                    # DECRYPTED
│   ├── admin                      # DECRYPTED user data
│   ├── backup                     # DECRYPTED user data
│   ├── operator                   # DECRYPTED user data
│   └── ...
├── key/
│   ├── version                    # DECRYPTED
│   ├── myKey1                     # DECRYPTED key metadata (priv removed)
│   ├── myKey1.pem.age             # PRIVATE KEY (age-encrypted PEM)
│   ├── MyAESKey                   # DECRYPTED key metadata (priv removed)
│   ├── MyAESKey.raw.age           # PRIVATE KEY (age-encrypted raw)
│   └── ...
├── namespace/
│   ├── version                    # DECRYPTED
│   ├── namespace1                 # DECRYPTED namespace data
│   └── ...
├── config/
│   ├── backup-key                 # Plain (base64-decoded)
│   ├── backup-salt                # Plain (base64-decoded)
│   ├── certificate                # Plain (base64-decoded)
│   ├── private-key                # Plain (base64-decoded PEM)
│   └── ...
└── domain-key/
    └── attended                   # Plain (base64-decoded)
```

---

## Workflow

The decryption process is a two-step workflow:

### Step 1: Export Backup to JSON with `export_backup.py`

First, use the existing `export_backup.py` tool to decrypt the backup passphrase layer:

```bash
python3 export_backup.py <backup_passphrase> <backup_file> --output exported.json
```

**What this does**:
- Decrypts the outer backup encryption layer using the backup passphrase
- Exports all KV pairs as base64-encoded values to JSON
- Saves the locked domain key (still encrypted with unlock passphrase)

**What it does NOT do**:
- Does NOT decrypt the domain key
- Does NOT decrypt values from encrypted stores (`/authentication/`, `/key/`, `/namespace/`)

### Step 2: Fully Decrypt with `decrypt_backup.py`

Then, use `decrypt_backup.py` to unlock the domain key, decrypt all encrypted values, and encrypt private keys with age:

```bash
python3 decrypt_backup.py <exported_json> -o <output_dir> --passphrase
# OR
python3 decrypt_backup.py <exported_json> -o <output_dir> --recipient <age_or_ssh_pubkey>
```

**What this does**:
- Prompts for unlock passphrase interactively (from terminal only)
- Unlocks the domain key using the unlock passphrase
- Derives per-store encryption keys from the domain key (using SHA-256)
- Decrypts all values from encrypted stores
- Extracts private keys from `/key/` entries and removes them from JSON
- Encrypts private keys with age (passphrase or recipient-based)
- Creates a directory structure mirroring the KV store layout

---

## Encryption Details

### Backup Passphrase Layer

- **Algorithm**: AES-256-GCM
- **Key Derivation**: scrypt with N=16384, r=8, p=16
- **Salt**: 16 bytes, stored in backup
- **ADATA**: Different for each field ("backup-version", "domain-key", "backup")
- **Handled by**: `export_backup.py`

### Domain Key Unlocking

- **Algorithm**: AES-256-GCM
- **Key Derivation**: scrypt with N=16384, r=8, p=16
- **Salt**: Stored separately in `/config/unlock-salt` (base64-encoded, 16 bytes)
- **ADATA**: "passphrase" (matches [hsm.ml:804](../hsm.ml#L804))
- **Format**: The locked domain key (in `.locked-domain-key`) is AES-GCM encrypted data without salt prefix
- **Handled by**: `decrypt_backup.py`

### Per-Store Encryption

The domain key is used to derive three separate encryption keys (matching [hsm.ml:808-809](../hsm.ml#L808-L809)):

```python
auth_store_key = SHA256(domain_key || "auth_store")
key_store_key = SHA256(domain_key || "key_store")
namespace_store_key = SHA256(domain_key || "namespace_store")
```

Each encrypted value uses:
- **Algorithm**: AES-256-GCM
- **ADATA**: Full key path (e.g., "/authentication/admin") - matches [encrypted_store.ml:90](../encrypted_store.ml#L90)
- **Format**: nonce (12 bytes) + ciphertext + tag (16 bytes)
- **Handled by**: `decrypt_backup.py`

### Which Stores Are Encrypted?

| Store Prefix | Encrypted? | Key Used |
|--------------|-----------|----------|
| `/authentication/` | ✓ Yes | SHA256(domain_key + "auth_store") |
| `/key/` | ✓ Yes | SHA256(domain_key + "key_store") |
| `/namespace/` | ✓ Yes | SHA256(domain_key + "namespace_store") |
| `/config/` | ✗ No | N/A (only base64 encoded) |
| `/domain-key/` | ✗ No | N/A (only base64 encoded) |
| `/.initialized` | ✗ No | N/A (empty file) |

---

## Testing

A test file is provided: [test_backup.json](test_backup.json)

This file contains an example backup export that you can use to test the decryption tool.

**Test unlock passphrase**: `UnlockPassphrase`

Example test:
```bash
python3 decrypt_backup.py test_backup.json -o /tmp/test_output --recipient age1xc0nx0dtqdlqywmfwt2ac2hvh90w0lz7g5utysklwaruv4rju55qk40mma
# Enter unlock passphrase: UnlockPassphrase
```

---

## Troubleshooting

### "Authentication tag verification failed"

- **Cause**: Wrong unlock passphrase or corrupted data
- **Solution**: Verify you're using the correct unlock passphrase (not the backup passphrase)

### "No .locked-domain-key found in JSON"

- **Cause**: JSON file was not created by `export_backup.py`
- **Solution**: First run `export_backup.py` to create a proper JSON export

