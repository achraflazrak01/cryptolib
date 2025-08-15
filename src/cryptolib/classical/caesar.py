from typing import Iterable

A0 = ord("A")

def _clean(text: str) -> str:
    """Keep only A-Z and uppercase them."""
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")

def _shift_char(ch: str, k: int) -> str:
    """Shift one uppercase letter by k (mod 26)."""
    return chr(((ord(ch) - A0 + (k % 26)) % 26) + A0)

def encrypt(plaintext: str, shift: int) -> str:
    """Caesar encryption on A-Z (non-letters removed)."""
    s = _clean(plaintext)
    return "".join(_shift_char(c, shift) for c in s)

def decrypt(ciphertext: str, shift: int) -> str:
    """Decrypt by shifting -k (mod 26)."""
    return encrypt(ciphertext, -shift)
