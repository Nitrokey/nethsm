#!/bin/bash
# Setup virtual environment for NetHSM backup decryption tools
#
# This script creates a Python virtual environment and installs
# the required dependencies for decrypt_backup.py and export_backup.py
#
# Copyright 2025, Nitrokey GmbH
# SPDX-License-Identifier: EUPL-1.2

set -e  # Exit on error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/venv"

echo "NetHSM Backup Tools - Virtual Environment Setup"
echo "================================================"
echo

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "Error: python3 is not installed or not in PATH"
    echo "Please install Python 3.7 or later"
    exit 1
fi

PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Found Python $PYTHON_VERSION"

# Check if venv already exists
if [ -d "$VENV_DIR" ]; then
    echo
    echo "Virtual environment already exists at: $VENV_DIR"
    read -p "Do you want to recreate it? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo "Removing existing virtual environment..."
        rm -rf "$VENV_DIR"
    else
        echo "Keeping existing virtual environment."
        echo "To activate it, run: source $VENV_DIR/bin/activate"
        exit 0
    fi
fi

# Create virtual environment
echo
echo "Creating virtual environment in: $VENV_DIR"
python3 -m venv "$VENV_DIR"
echo "✓ Virtual environment created"

# Activate virtual environment
echo
echo "Activating virtual environment..."
source "$VENV_DIR/bin/activate"

# Upgrade pip
echo
echo "Upgrading pip..."
pip install --upgrade pip --quiet
echo "✓ pip upgraded to $(pip --version | awk '{print $2}')"

# Install dependencies
echo
echo "Installing dependencies..."
echo "  - scrypt (for key derivation)"
echo "  - cryptography (for AES-GCM encryption)"
echo "  - pyrage (for age encryption)"
pip install scrypt cryptography pyrage --quiet

# Verify installations
echo
echo "Verifying installations..."
python3 -c "import scrypt; print('  ✓ scrypt:', scrypt.__version__ if hasattr(scrypt, '__version__') else 'installed')"
python3 -c "import cryptography; print('  ✓ cryptography:', cryptography.__version__)"
python3 -c "import pyrage; print('  ✓ pyrage:', pyrage.__version__ if hasattr(pyrage, '__version__') else 'installed')"

echo
echo "================================================"
echo "Setup complete!"
echo
echo "To use the backup decryption tools:"
echo
echo "  1. Activate the virtual environment:"
echo "     source $VENV_DIR/bin/activate"
echo
echo "  2. Run the tools:"
echo "     python3 export_backup.py <backup_pass> backup.bin -o exported.json"
echo "     python3 decrypt_backup.py exported.json -o decrypted/ --passphrase"
echo "     (age and unlock passphrases will be prompted interactively)"
echo
echo "  3. When finished, deactivate the environment:"
echo "     deactivate"
echo
echo "Note: You can also use the convenience wrapper script:"
echo "  ./run_decrypt.sh exported.json -o decrypted/ --passphrase"
echo
echo "Age encryption options for private keys (one required):"
echo "  --passphrase                  Encrypt with passphrase (prompted interactively)"
echo "  --recipient <pubkey>          Encrypt with age or SSH public key"
echo "  --recipients-file <file>      Encrypt with recipients from file"
echo
