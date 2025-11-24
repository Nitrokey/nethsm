#!/usr/bin/env python3

import os
import struct
import json
import base64
import scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag


def read_file(filename):
    filesize = os.path.getsize(filename)
    with open(filename, 'rb') as file:
        return file.read()


def decode_length(data):
    b, l = struct.unpack('>B H', data[:3])
    return (b << 16) + l


def get_field(data):
    len = decode_length(data)
    field = data[3:3+len]
    rest = data[3+len:]
    return field, rest


def decrypt(key, adata, data):
    iv_size = 12
    ciphertext = data[iv_size:-16]
    tag = data[-16:]
    nonce = data[:iv_size]

    cipher = Cipher(algorithms.AES(key), modes.GCM(
        nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(adata)

    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except InvalidTag:
        raise Exception(
            "Authentication tag verification failed. The data may be tampered.")


def export(passphrase, backup_image_filename, output):
    with open(backup_image_filename, 'rb') as file:
        backup_data = file.read()

    header_len = len(b"_NETHSM_BACKUP_")
    header = backup_data[:header_len]
    version = backup_data[header_len]
    backup_data = backup_data[header_len + 1:]

    if not header.startswith(b"_NETHSM_BACKUP_"):
        raise Exception("Not a NetHSM backup file")

    if version != 0:
        raise Exception(
            f"Version mismatch on export, provided backup version is {version}, this tool expects 0")

    salt, backup_data = get_field(backup_data)

    scrypt_n = 16384
    scrypt_r = 8
    scrypt_p = 16
    salt_bytes = salt
    key = scrypt.hash(passphrase.encode(), salt_bytes,
                      scrypt_n, scrypt_r, scrypt_p, 32)

    adata = b"backup-version"
    encrypted_version, backup_data = get_field(backup_data)
    version_int = decrypt(key, adata, encrypted_version)
    if version != version_int[0]:
        raise Exception("Internal and external version mismatch.")

    adata = b"domain-key"
    encrypted_domain_key, backup_data = get_field(backup_data)
    locked_domain_key = decrypt(key, adata, encrypted_domain_key)

    kvs = []
    while backup_data:
        item, backup_data = get_field(backup_data)
        adata = b"backup"
        key_value_pair = decrypt(key, adata, item)
        k, v = get_field(key_value_pair)
        kvs.append((k.decode(), base64.b64encode(v).decode()))

    data = {
        ".locked-domain-key": base64.b64encode(locked_domain_key).decode(), **dict(kvs)}

    if output:
        with open(output, 'w') as output_file:
            json.dump(data, output_file, indent=4)
    else:
        print(json.dumps(data, indent=4))


if __name__ == "__main__":
    import sys
    import argparse
    parser = argparse.ArgumentParser(
        description="Export a NetHSM backup image to JSON")
    parser.add_argument("passphrase", help="Backup passphrase")
    parser.add_argument("backup_image_filename", help="Backup image filename")
    parser.add_argument("--output", help="Output filename")
    args = parser.parse_args()
    export(args.passphrase, args.backup_image_filename, args.output)
