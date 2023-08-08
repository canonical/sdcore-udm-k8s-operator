#!/usr/bin/env python3
# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""Module for generating encryption key generation."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def generate_x25519_private_key() -> str:
    """Generate X25519 private key and return it as hexadecimal string.

    Returns:
        str: X25519 private key as hexadecimal string.
    """
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return private_bytes.hex()
