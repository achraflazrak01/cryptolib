from math import gcd
from cryptolib.exceptions import InvalidKeyError
from cryptolib.mathutils.number import modinv

def mod26_det(M: list[list[int]]) -> int:
    (a, b), (c, d) = M
    return (a * d - b * c) % 26

def is_invertible_mod26(M: list[list[int]]) -> bool:
    return gcd(mod26_det(M), 26) == 1

def inv2x2_mod26(M: list[list[int]]) -> list[list[int]]:
    (a, b), (c, d) = M
    det = mod26_det(M)
    if not is_invertible_mod26(M):
        raise InvalidKeyError("Hill key not invertible mod 26")
    di = modinv(det, 26)
    return [
        [(d * di) % 26, (-b * di) % 26],
        [(-c * di) % 26, (a * di) % 26],
    ]
