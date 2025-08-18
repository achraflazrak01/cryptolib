from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)

from cryptography.exceptions import InvalidSignature

def ed25519_keygen():
    """
    Return (sk, pk) where:
        - sk: Ed25519PrivateKey
        - pk: Ed25519PublicKey
    """
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return sk, pk

def ed25519_sign(sk: Ed25519PrivateKey, msg: bytes) -> bytes:
    """Return signature bytes for msg."""
    return sk.sign(msg)

def ed25519_verify(pk: Ed25519PublicKey, msg: bytes, sig: bytes) -> bool:
    """Return True iff signature verifies; False otherwise."""
    try:
        pk.verify(sig, msg)
        return True
    except InvalidSignature:
        return False
