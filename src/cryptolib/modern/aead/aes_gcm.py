import os
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12 # 96-bit nonce as recommended for GCM

def encrypt(key: bytes, plaintext: bytes, aad: Optional[bytes] = None) -> tuple[bytes, bytes]:
    """
    Encrypt with AES-GCM. Returns (nonce, ciphertext_with_tag).
    Key must be 16/24/32 bytes (AES-128/192/256).
    """
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct

def decrypt(key: bytes, nonce: bytes, ciphertext_with_tag: bytes, aad: Optional[bytes] = None) -> bytes:
    """
    Decrypt with AES-GCM. Raises InvalidTag on tampering or wrong inputs.
    """
    if len(nonce) != NONCE_LEN:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    return AESGCM(key).decrypt(nonce, ciphertext_with_tag, aad)
