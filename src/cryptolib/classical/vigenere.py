from cryptolib.exceptions import ValidationError

A0 = ord("A")

def _clean_text(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z")

def _clean_key(key: str) -> str:
    k = "".join(ch for ch in key.upper() if "A" <= ch <= "Z")
    if not k:
        raise ValidationError("Vigenère key must contain at least one A-Z letter")
    return k

def _shift_char(ch: str, k: int) -> str:
    return chr(((ord(ch) - A0 + k) % 26) + A0)

def encrypt(plaintext: str, key: str) -> str:
    s = _clean_text(plaintext)
    k = _clean_key(key)
    out = []
    for i, ch in enumerate(s):
        ki = ord(k[i % len(k)]) - A0
        out.append(_shift_char(ch, ki))
    return "".join(out)

def decrypt(ciphertext: str, key: str) -> str:
    s = _clean_text(ciphertext)
    k = _clean_key(key)
    out = []
    for i, ch in enumerate(s):
        ki = ord(k[i % len(k)]) - A0
        out.append(_shift_char(ch, -ki))
    return "".join(out)
