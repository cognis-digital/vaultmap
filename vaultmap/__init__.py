"""VAULTMAP - Personal asset & account inventory, estate-planning-grade encrypted.

A zero-install, standard-library-only tool for maintaining an encrypted
inventory of accounts, assets, and instructions for executors/heirs.
"""
from .core import (
    Vault,
    VaultError,
    Entry,
    derive_key,
    encrypt_blob,
    decrypt_blob,
)

TOOL_NAME = "vaultmap"
TOOL_VERSION = "1.0.0"

__all__ = [
    "Vault",
    "VaultError",
    "Entry",
    "derive_key",
    "encrypt_blob",
    "decrypt_blob",
    "TOOL_NAME",
    "TOOL_VERSION",
]
