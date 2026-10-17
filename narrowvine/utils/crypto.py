"""Cryptography helpers built on PyCryptodomeX (``Cryptodome``)."""

from __future__ import annotations

from Cryptodome.Cipher import AES


def pkcs7_unpad(data: bytes, block_size: int = AES.block_size) -> bytes:
    """Strip PKCS#7 padding (no-op if the padding is absent/invalid)."""
    if not data:
        return data
    padding = data[-1]
    if 1 <= padding <= block_size and data[-padding:] == bytes([padding]) * padding:
        return data[:-padding]
    return data


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    """AES-CBC decrypt and strip PKCS#7 padding (HLS AES-128 segments)."""
    key, iv = bytes(key), bytes(iv)
    if len(key) != 16:
        raise ValueError(f"AES-128 key must be 16 bytes, got {len(key)}")
    if len(iv) != AES.block_size:
        raise ValueError(f"IV must be {AES.block_size} bytes, got {len(iv)}")
    return pkcs7_unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data))
