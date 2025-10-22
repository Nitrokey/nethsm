# NetHSM Backup Decryption Tool

This directory contains a tool for fully decrypting NetHSM backup files exported as JSON.

## Overview

NetHSM backups use a multi-layer encryption scheme:

1. **Backup Passphrase Layer** (outermost): Encrypts the entire backup with AES-256-GCM using a key derived from the backup passphrase via scrypt
2. **Domain Key Layer**: The domain key itself is encrypted with the unlock passphrase
3. **Store-specific Encryption** (innermost): Keys in `/authentication/`, `/key/`, and `/namespace/` stores are encrypted with keys derived from the domain key using SHA-256
4. **Private Key Protection**: Extracted private keys from `/key/` are encrypted with age (either passphrase or recipient-based)

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

### Private Key Encryption with Age

Private keys extracted from `/key/` entries are re-encrypted using the age encryption format:

- **Algorithm**: age (ChaCha20-Poly1305 with X25519 or scrypt)
- **Format**: Armored age format (ASCII-encoded)
- **Options**:
  - **Passphrase**: scrypt-based encryption (passphrase must be ≥10 characters)
  - **Age Recipient**: X25519 public key (e.g., `age1ql3z7hjy...`)
  - **SSH Recipient**: SSH public key (e.g., `ssh-ed25519 AAAAC3...`)
- **Output**: `.pem.age` or `.raw.age` files
- **Handled by**: `decrypt_backup.py` using pyrage library

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

## Tool: `decrypt_backup.py`

### Usage

```bash
python3 decrypt_backup.py <json_file> [-o output_dir] <age_encryption_option>
```

### Arguments

- `json_file`: Path to the exported backup JSON file (created by `export_backup.py`)
- `-o, --output`: Output directory for decrypted files (default: `backup_decrypted`)

### Age Encryption Options (REQUIRED - choose one)

- `--passphrase`: Encrypt private keys with passphrase (prompted interactively, min 10 characters, confirmed)
- `--recipient <pubkey>`: Encrypt with age or SSH public key (can be specified multiple times)
- `--recipients-file <file>`: File containing recipient public keys (one per line)

### Interactive Passphrases

All passphrases are prompted interactively from the terminal for security:

1. **Unlock passphrase**: Prompted first (before loading JSON)
2. **Age passphrase**: Prompted after successful unlock (only if `--passphrase` is used)
   - Asked twice for confirmation
   - Must be at least 10 characters
   - Passphrases must match

**Security**: The script rejects stdin redirection and only accepts terminal input.

### Examples

**With age passphrase encryption:**
```bash
python3 decrypt_backup.py exported.json -o decrypted/ --passphrase
# Prompts:
# Enter unlock passphrase: [hidden]
# Enter age encryption passphrase: [hidden]
# Confirm age encryption passphrase: [hidden]
```

**With age recipient:**
```bash
python3 decrypt_backup.py exported.json -o decrypted/ --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# Prompts:
# Enter unlock passphrase: [hidden]
```

**With SSH recipient:**
```bash
python3 decrypt_backup.py exported.json -o decrypted/ --recipient "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhzcEZvKk0q7ZqN1NLeIOnRMP2QZMvWYuhe6kKqun2w"
# Prompts:
# Enter unlock passphrase: [hidden]
```

**With multiple recipients:**
```bash
python3 decrypt_backup.py exported.json -o decrypted/ --recipient age1abc... --recipient age1xyz...
```

**With recipients file:**
```bash
# recipients.txt contains:
# age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
# ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhzcEZvKk0q7ZqN1NLeIOnRMP2QZMvWYuhe6kKqun2w

python3 decrypt_backup.py exported.json -o decrypted/ --recipients-file recipients.txt
```

### Output

The tool creates:
1. A directory structure mirroring the KV store
2. Decrypted files for encrypted stores
3. Base64-decoded files for non-encrypted values
4. `.pem.age` or `.raw.age` files containing age-encrypted private keys
5. JSON files in `/key/` with `priv` field removed
6. `DECRYPTION_SUMMARY.json` - summary of the decryption process (includes private key count)

### Decrypting Age-Encrypted Private Keys

To decrypt the age-encrypted private keys later:

**With passphrase:**
```bash
age -d /path/to/key.pem.age > key.pem
# (will prompt for passphrase)
```

**With identity file:**
```bash
age -d -i identity.txt /path/to/key.pem.age > key.pem
```

**With SSH key:**
```bash
age -d -i ~/.ssh/id_ed25519 /path/to/key.pem.age > key.pem
```

---

## Security Considerations

⚠️ **WARNING**: The decrypted output contains highly sensitive cryptographic material:
- Private keys (in age-encrypted `.pem.age` and `.raw.age` files)
- User credentials (password hashes)
- Key metadata for cryptographic operations
- Authentication secrets

**Recommendations**:
1. Only decrypt backups in secure, isolated environments
2. Private keys are protected with age encryption - ensure you have secure access to:
   - The age passphrase (if using `--passphrase`)
   - The age identity file (if using `--recipient`)
3. Delete decrypted output immediately after use
4. Never commit decrypted backups to version control
5. Ensure proper file permissions (e.g., `chmod 700` on output directory)
6. Use encrypted storage if decrypted backups must be preserved
7. Age-encrypted private keys (`.pem.age`, `.raw.age`) can be safely stored as they are encrypted

**Passphrase Security**:
- All passphrases are prompted interactively (not via command-line arguments)
- Stdin redirection is rejected for security
- Age passphrases must be at least 10 characters
- Age passphrases are confirmed (asked twice) to prevent typos

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

## Code References

The implementation is based on the following OCaml source files:

- [hsm.ml:808-809](../hsm.ml#L808-L809) - Domain key derivation with SHA-256
- [hsm.ml:2830-2989](../hsm.ml#L2830-L2989) - Backup restore logic
- [encrypted_store.ml:90-93](../encrypted_store.ml#L90-L93) - Per-value encryption with key path as ADATA
- [domain_key_store.ml:16-24](../domain_key_store.ml#L16-L24) - Domain key encryption/decryption
- [crypto.ml:24-26](../crypto.ml#L24-L26) - Scrypt key derivation parameters

---

## Setup and Dependencies

### Automated Setup (Recommended)

Use the provided setup script to create a virtual environment with all dependencies:

```bash
./setup_venv.sh
```

This will:
- Create a Python virtual environment in `./venv/`
- Install required packages: `scrypt`, `cryptography`, `pyrage`
- Verify the installation

After setup, activate the virtual environment before running the scripts:

```bash
source venv/bin/activate
python3 decrypt_backup.py exported.json -o decrypted/ --passphrase
deactivate  # when done
```

### Manual Setup

If you prefer to install dependencies manually:

```bash
pip3 install scrypt cryptography pyrage
```

Or for the current user only:

```bash
pip3 install --user scrypt cryptography pyrage
```

### Required Packages

Both `export_backup.py` and `decrypt_backup.py` require:
- Python 3.7 or later
- `scrypt` - For key derivation (scrypt KDF)
- `cryptography` - For AES-GCM encryption/decryption
- `pyrage` - For age encryption of private keys (decrypt_backup.py only)

---

## Troubleshooting

### "Authentication tag verification failed"

- **Cause**: Wrong unlock passphrase or corrupted data
- **Solution**: Verify you're using the correct unlock passphrase (not the backup passphrase)

### "No .locked-domain-key found in JSON"

- **Cause**: JSON file was not created by `export_backup.py`
- **Solution**: First run `export_backup.py` to create a proper JSON export

### "ModuleNotFoundError: No module named 'scrypt'" or "No module named 'pyrage'"

- **Cause**: Required Python dependencies not installed
- **Solution**: Run `pip3 install scrypt cryptography pyrage`

### "Age encryption is required. Must specify one of: --passphrase, --recipient, or --recipients-file"

- **Cause**: No age encryption option specified
- **Solution**: Add one of the required flags: `--passphrase`, `--recipient`, or `--recipients-file`

### "Passphrases must be entered interactively from a terminal"

- **Cause**: Trying to pipe passphrase via stdin (e.g., `echo "pass" | python3 decrypt_backup.py ...`)
- **Solution**: Run the script directly in a terminal. Passphrases must be entered interactively for security.

### "Age passphrase must be at least 10 characters long"

- **Cause**: Age passphrase is too short
- **Solution**: Use a passphrase with at least 10 characters

### "Passphrases do not match"

- **Cause**: Age passphrase and confirmation don't match
- **Solution**: Ensure you type the same passphrase both times

### "Failed to process key entry: missing required 'priv' field"

- **Cause**: Key entry in `/key/` store doesn't have a private key component
- **Solution**: This indicates corrupted or invalid key data. Verify the backup file integrity.

### Permission errors

- **Cause**: Output directory permissions
- **Solution**: Ensure you have write permissions to the output directory

---

## License

Copyright 2025, Nitrokey GmbH
SPDX-License-Identifier: EUPL-1.2
