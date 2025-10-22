#!/usr/bin/env python3

"""
NetHSM Backup Decryption Tool

This tool decrypts values from an exported NetHSM backup JSON file (created by export_backup.py).

"""

import os
import sys
import struct
import json
import base64
import argparse
import hashlib
import scrypt
import getpass
from pathlib import Path
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
import pyrage
import pyrage.passphrase
from pyrage.x25519 import Recipient as X25519Recipient
from pyrage.ssh import Recipient as SSHRecipient


# Scrypt parameters (matching crypto.ml)
SCRYPT_N = 16384
SCRYPT_R = 8
SCRYPT_P = 16
KEY_LEN = 32


def decode_length(data):
    """Decode 3-byte length field (big-endian)"""
    b, l = struct.unpack('>B H', data[:3])
    return (b << 16) + l


def get_field(data):
    """Extract length-prefixed field from data"""
    length = decode_length(data)
    field = data[3:3+length]
    rest = data[3+length:]
    return field, rest


def decrypt_aes_gcm(key, adata, data):
    """Decrypt AES-GCM encrypted data

    Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
    """
    iv_size = 12
    tag_size = 16

    if len(data) <= iv_size + tag_size:
        raise ValueError("Insufficient data for decryption")

    nonce = data[:iv_size]
    ciphertext = data[iv_size:-tag_size]
    tag = data[-tag_size:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(adata)

    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except InvalidTag:
        raise Exception(
            "Authentication tag verification failed. Wrong key or corrupted data.")


def unlock_domain_key(locked_domain_key_b64, unlock_salt_b64, unlock_passphrase):
    """Unlock domain key from base64-encoded locked domain key

    The locked domain key is AES-GCM encrypted data (nonce + ciphertext + tag).
    The unlock salt is stored separately in /config/unlock-salt.
    """
    locked_domain_key = base64.b64decode(locked_domain_key_b64)
    unlock_salt = base64.b64decode(unlock_salt_b64)

    # Derive unlock key from passphrase using scrypt
    unlock_key = scrypt.hash(
        unlock_passphrase.encode(),
        unlock_salt,
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        KEY_LEN
    )

    # Decrypt domain key
    # The adata matches hsm.ml:804 encrypt_with_pass_key: "passphrase"
    adata = b"passphrase"
    domain_key = decrypt_aes_gcm(unlock_key, adata, locked_domain_key)

    return domain_key


def make_store_keys(domain_key):
    """Derive per-store encryption keys from domain key using SHA256

    This matches the OCaml code in hsm.ml:808-809:
    let extend k t = Digestif.SHA256.(digest_string (k ^ t) |> to_raw_string)
    (extend dk "auth_store", extend dk "key_store", extend dk "namespace_store")
    """
    def extend(key, tag):
        return hashlib.sha256(key + tag.encode()).digest()

    return {
        "authentication": extend(domain_key, "auth_store"),
        "key": extend(domain_key, "key_store"),
        "namespace": extend(domain_key, "namespace_store")
    }


def get_store_type(key_path):
    """Determine which encrypted store a key belongs to"""
    if key_path.startswith("/authentication/"):
        return "authentication"
    elif key_path.startswith("/key/"):
        return "key"
    elif key_path.startswith("/namespace/"):
        return "namespace"
    return None


def decrypt_kv_value(key_path, base64_value, store_keys):
    """Decrypt a KV value if it belongs to an encrypted store

    The adata for decryption is the full key path (matching encrypted_store.ml:90)
    """
    store_type = get_store_type(key_path)

    if store_type is None:
        # Not encrypted, just decode base64
        return base64.b64decode(base64_value)

    # Get the encryption key for this store
    encryption_key = store_keys[store_type]

    # Decode base64
    encrypted_data = base64.b64decode(base64_value)

    # Decrypt with full key path as adata
    adata = key_path.encode()
    decrypted_data = decrypt_aes_gcm(encryption_key, adata, encrypted_data)

    return decrypted_data


def safe_path(base_dir, key_path):
    """Create a safe filesystem path from a KV key path"""
    # Remove leading slash and dot
    if key_path.startswith("/"):
        key_path = key_path[1:]
    if key_path.startswith("."):
        key_path = key_path[1:]

    # Replace any remaining slashes to create directory structure
    path = os.path.join(base_dir, key_path)

    # Ensure we don't escape base_dir
    abs_base = os.path.abspath(base_dir)
    abs_path = os.path.abspath(path)
    if not abs_path.startswith(abs_base):
        raise ValueError(f"Unsafe path: {key_path}")

    return abs_path


def encrypt_with_age(data, passphrase=None, recipients=None, recipients_file=None):
    """Encrypt data using age with armor format

    Args:
        data: bytes to encrypt
        passphrase: optional passphrase for encryption
        recipients: optional list of recipient public keys (strings - age or SSH format)
        recipients_file: optional path to file containing recipient public keys

    Returns:
        Encrypted data in armored format (bytes)

    Notes:
        Recipients are auto-detected:
        - SSH keys (ssh-rsa, ssh-ed25519) use SSHRecipient
        - Age keys (age1...) use X25519Recipient
    """
    if isinstance(data, str):
        data = data.encode()

    # Build list of recipient strings
    recipient_strings = []

    if recipients:
        if isinstance(recipients, str):
            recipient_strings.append(recipients)
        else:
            recipient_strings.extend(recipients)

    if recipients_file:
        with open(recipients_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    recipient_strings.append(line)

    # Encrypt with passphrase or recipients
    if passphrase:
        encrypted = pyrage.passphrase.encrypt(data, passphrase, armored=True)
    elif recipient_strings:
        # Convert strings to Recipient objects
        # Auto-detect SSH vs age recipients
        recipient_objects = []
        for r in recipient_strings:
            # SSH keys start with ssh-rsa or ssh-ed25519
            if r.startswith(('ssh-rsa', 'ssh-ed25519')):
                recipient_objects.append(SSHRecipient.from_str(r))
            else:
                # Assume age format (age1...)
                recipient_objects.append(X25519Recipient.from_str(r))

        encrypted = pyrage.encrypt(data, recipient_objects, armored=True)
    else:
        raise ValueError("Either passphrase or recipients must be provided for age encryption")

    return encrypted


def decrypt_from_json(json_file, unlock_passphrase, output_dir, use_age_passphrase=False, age_recipients=None, age_recipients_file=None):
    """Decrypt all values from an exported backup JSON"""

    # Load JSON
    with open(json_file, 'r') as f:
        data = json.load(f)

    print(f"✓ Loaded JSON with {len(data)} entries")

    # Extract and unlock domain key
    if ".locked-domain-key" not in data:
        raise ValueError("No .locked-domain-key found in JSON. This file must be created by export_backup.py")

    if "/config/unlock-salt" not in data:
        raise ValueError("No /config/unlock-salt found in JSON. This file must be a complete backup export.")

    locked_domain_key_b64 = data[".locked-domain-key"]
    unlock_salt_b64 = data["/config/unlock-salt"]
    domain_key = unlock_domain_key(locked_domain_key_b64, unlock_salt_b64, unlock_passphrase)
    print(f"✓ Unlocked domain key with unlock passphrase")

    # Derive store keys
    store_keys = make_store_keys(domain_key)
    print(f"✓ Derived store encryption keys (auth, key, namespace)")

    # Now that we've successfully unlocked the domain key, prompt for age passphrase if needed
    age_passphrase = None
    if use_age_passphrase:
        try:
            while True:
                age_passphrase = getpass.getpass("Enter age encryption passphrase: ")
                # Validate minimum length
                if len(age_passphrase) < 10:
                    print("Error: Age passphrase must be at least 10 characters long", file=sys.stderr)
                    continue

                age_passphrase_confirm = getpass.getpass("Confirm age encryption passphrase: ")

                if age_passphrase == age_passphrase_confirm:
                    break
                else:
                    print("Error: Passphrases do not match. Please try again.", file=sys.stderr)
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"\n\nError reading age passphrase: {e}", file=sys.stderr)
            sys.exit(1)

    # Create output directory
    os.makedirs(output_dir, exist_ok=True)

    # Save domain key for reference
    # domain_key_path = os.path.join(output_dir, ".domain-key")
    # with open(domain_key_path, 'wb') as f:
    #     f.write(domain_key)
    # print(f"✓ Saved unlocked domain key")

    # Save locked domain key for reference
    locked_domain_key_path = os.path.join(output_dir, ".locked-domain-key")
    with open(locked_domain_key_path, 'w') as f:
        f.write(locked_domain_key_b64)

    # Process all KV pairs
    encrypted_count = 0
    plain_count = 0
    failed_count = 0
    priv_key_count = 0

    for key_path, base64_value in data.items():
        if key_path.startswith("."):
            # Skip special keys (already processed)
            continue

        try:
            # Create output path
            file_path = safe_path(output_dir, key_path)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)

            # Decrypt value
            store_type = get_store_type(key_path)
            if store_type:
                decrypted_value = decrypt_kv_value(key_path, base64_value, store_keys)

                # Special handling for /key/ entries - extract and save priv object separately
                if key_path.startswith("/key/"):
                    # Skip .version files which don't contain keys
                    if not key_path.endswith("/.version"):
                        try:
                            # Try to parse as JSON
                            key_json = json.loads(decrypted_value)

                            # All /key/ entries (except .version) MUST have a "priv" field
                            if not isinstance(key_json, dict):
                                raise ValueError(f"Key entry is not a JSON object: {key_path}")

                            if "priv" not in key_json:
                                raise ValueError(f"Key entry missing required 'priv' field: {key_path}")

                            priv_obj = key_json["priv"]

                            # Save the priv content to a separate file (always encrypted)
                            if not isinstance(priv_obj, dict):
                                raise ValueError(f"'priv' field is not a JSON object in {key_path}")

                            if "PEM" in priv_obj:
                                # Save PEM format (encrypted)
                                pem_data = priv_obj["PEM"]
                                priv_file_path = file_path + ".pem.age"
                                encrypted_pem = encrypt_with_age(
                                    pem_data,
                                    passphrase=age_passphrase,
                                    recipients=age_recipients,
                                    recipients_file=age_recipients_file
                                )
                                with open(priv_file_path, 'wb') as f:
                                    f.write(encrypted_pem)
                                print(f"    → Saved encrypted private key (PEM): {key_path}.pem.age")
                                priv_key_count += 1
                            elif "raw" in priv_obj:
                                # Save raw format (base64 encoded, needs decoding)
                                raw_data = priv_obj["raw"]
                                # Decode base64
                                if isinstance(raw_data, str):
                                    decoded_raw = base64.b64decode(raw_data)
                                else:
                                    # If not a string, convert to string first then decode
                                    decoded_raw = base64.b64decode(str(raw_data))

                                # Encrypt and save
                                priv_file_path = file_path + ".raw.age"
                                encrypted_raw = encrypt_with_age(
                                    decoded_raw,
                                    passphrase=age_passphrase,
                                    recipients=age_recipients,
                                    recipients_file=age_recipients_file
                                )
                                with open(priv_file_path, 'wb') as f:
                                    f.write(encrypted_raw)
                                print(f"    → Saved encrypted private key (raw): {key_path}.raw.age")
                                priv_key_count += 1
                            else:
                                raise ValueError(f"'priv' object has neither 'PEM' nor 'raw' field in {key_path}")

                            # Remove priv object from JSON
                            del key_json["priv"]

                            # Save modified JSON without priv
                            decrypted_value = json.dumps(key_json, indent=2).encode()

                        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as e:
                            # Re-raise with context - this should fail
                            raise Exception(f"Failed to process key entry {key_path}: {e}")

                # Write decrypted value
                with open(file_path, 'wb') as f:
                    f.write(decrypted_value)

                # Also save encrypted version for reference
                # encrypted_path = file_path + ".encrypted.b64"
                # with open(encrypted_path, 'w') as f:
                #     f.write(base64_value)

                encrypted_count += 1
                print(f"  → Decrypted: {key_path}")
            else:
                # Plain value, just decode base64
                plain_value = base64.b64decode(base64_value)
                with open(file_path, 'wb') as f:
                    f.write(plain_value)
                plain_count += 1
                print(f"  → Decoded: {key_path}")

        except Exception as e:
            print(f"  ✗ Failed to process {key_path}: {e}")
            failed_count += 1

    print(f"\n✓ Decryption complete!")
    print(f"  - Encrypted values decrypted: {encrypted_count}")
    print(f"  - Plain values saved: {plain_count}")
    print(f"  - Private keys extracted: {priv_key_count}")
    print(f"  - Failed: {failed_count}")
    print(f"  - Output directory: {output_dir}")

    # Create a summary file
    summary = {
        "json_file": json_file,
        "total_entries": len(data),
        "encrypted_decrypted": encrypted_count,
        "plain_values": plain_count,
        "private_keys_extracted": priv_key_count,
        "failed": failed_count,
        "stores": {
            "authentication": "Encrypted with SHA256(domain_key + 'auth_store')",
            "key": "Encrypted with SHA256(domain_key + 'key_store')",
            "namespace": "Encrypted with SHA256(domain_key + 'namespace_store')"
        }
    }

    summary_path = os.path.join(output_dir, "DECRYPTION_SUMMARY.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    print(f"  - Summary saved to: DECRYPTION_SUMMARY.json")


def main():
    parser = argparse.ArgumentParser(
        description="Decrypt values from an exported NetHSM backup JSON (created by export_backup.py)",
        epilog="""
Examples:
  # First, export the backup to JSON using export_backup.py:
  python3 export_backup.py MyBackupPass backup.bin --output exported.json

  # Decrypt and encrypt private keys with age using a passphrase:
  %(prog)s exported.json -o decrypted/ --passphrase
  (will prompt for unlock passphrase, then age passphrase twice for confirmation)

  # Decrypt and encrypt private keys with age using recipient public keys:
  %(prog)s exported.json -o decrypted/ --recipient age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p

  # Decrypt and encrypt private keys using SSH recipient:
  %(prog)s exported.json -o decrypted/ --recipient "ssh-ed25519 AAAAC3Nza..."

  # Decrypt and encrypt private keys using a recipients file:
  %(prog)s exported.json -o decrypted/ --recipients-file recipients.txt

  # Multiple recipients:
  %(prog)s exported.json -o decrypted/ --recipient age1ql3... --recipient age1abc...

This will create a directory structure with all decrypted files.
Private keys are always encrypted with age and saved as .pem.age or .raw.age files.

All passphrases are prompted interactively from the terminal for security.
        """
    )

    parser.add_argument(
        "json_file",
        help="Path to the exported backup JSON file (from export_backup.py)"
    )

    parser.add_argument(
        "-o", "--output",
        default="backup_decrypted",
        help="Output directory for decrypted files (default: backup_decrypted)"
    )

    # Age encryption options (REQUIRED)
    age_group = parser.add_argument_group('age encryption options (REQUIRED)',
                                          'Private keys must be encrypted using age. Specify one encryption method:')

    age_group.add_argument(
        "--passphrase",
        dest="use_age_passphrase",
        action="store_true",
        help="Encrypt with passphrase (will be prompted interactively with confirmation, min 10 characters)"
    )

    age_group.add_argument(
        "--recipient",
        dest="age_recipients",
        action="append",
        help="Recipient public key for age encryption (can be specified multiple times)"
    )

    age_group.add_argument(
        "--recipients-file",
        dest="age_recipients_file",
        help="File containing recipient public keys (one per line)"
    )

    args = parser.parse_args()

    # Ensure we're running from a terminal (not stdin redirection)
    if not sys.stdin.isatty():
        print("Error: Passphrases must be entered interactively from a terminal.", file=sys.stderr)
        print("Standard input redirection is not allowed for security reasons.", file=sys.stderr)
        sys.exit(1)

    # Validate age encryption options - must specify exactly one method
    has_recipients = args.age_recipients or args.age_recipients_file

    if args.use_age_passphrase and has_recipients:
        parser.error("Cannot use --passphrase with --recipient or --recipients-file")

    if not args.use_age_passphrase and not has_recipients:
        parser.error("Age encryption is required. Must specify one of: --passphrase, --recipient, or --recipients-file")

    # Prompt for unlock passphrase first (before loading JSON)
    try:
        unlock_passphrase = getpass.getpass("Enter unlock passphrase: ")
        if not unlock_passphrase:
            print("Error: Unlock passphrase cannot be empty", file=sys.stderr)
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError reading unlock passphrase: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        decrypt_from_json(
            args.json_file,
            unlock_passphrase,
            args.output,
            use_age_passphrase=args.use_age_passphrase,
            age_recipients=args.age_recipients,
            age_recipients_file=args.age_recipients_file
        )
    except Exception as e:
        print(f"\n✗ Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
