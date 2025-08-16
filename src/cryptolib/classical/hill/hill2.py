from cryptolib.exceptions import InvalidKeyError
from .helpers import is_invertible_mod26, inv2x2_mod26

A0 = ord("A")

def _clean(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z")

def _pairs(text: str) -> list[str]:
    s = _clean(text)
    if len(s) % 2 == 1:
        s += "X"
    return [s[i: i + 2] for i in range(0, len(s), 2)]

def _vec2(pair: str) -> list[int]:
    return [ord(pair[0]) - A0, ord(pair[1]) - A0]

def _letters(v: list[int]) -> str:
    return "".join(chr((x % 26) + A0) for x in v)

def _mulK_vec(K: list[list[int]], v: list[int]) -> list[int]:
    return [
        (K[0][0] * v[0] + K[0][1] * v[1]) % 26,
        (K[1][0] * v[0] + K[1][1] * v[1]) % 26,
    ]

def encrypt(plaintext: str,  K: list[list[int]]) -> str:
    if not is_invertible_mod26(K):
        raise InvalidKeyError("Key not invertible mod 26")
    out = []
    for pair in _pairs(plaintext):
        v = _vec2(pair)
        c = _mulK_vec(K, v)
        out.append(_letters(c))
    return "".join(out)

def decrypt(ciphertext: str, K: list[list[int]]) -> str:
    Ki = inv2x2_mod26(K)
    s = _clean(ciphertext)
    if len(s) % 2 == 1:
        s += "X"
    out = []
    i = 0
    while i < len(s):
        v = [ord(s[i]) - A0, ord(s[i + 1]) - A0]
        p = _mulK_vec(Ki, v)
        out.append(_letters(p))
        i += 2
    return "".join(out)
