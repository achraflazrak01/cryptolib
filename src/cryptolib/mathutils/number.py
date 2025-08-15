from typing import Tuple
from cryptolib.exceptions import NotInvertibleError

def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean algorithm (iterative).
    Returns (g, x, y) with g = gcd(a, b) and a*x + b*y = g
    g is always non-negative.
    """
    old_r, r = a, b
    old_s, s = 1, 0 # coefficients for 'a'
    old_t, t = 0, 1 # coefficients for 'b'
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    # normalize gcd to be non-negative
    if old_r < 0:
        old_r, old_s, old_t = -old_r, -old_s, -old_t
    return old_r, old_s, old_t

def modinv(a: int, n: int) -> int:
    """
    Modular inverse of a modulo n using egcd.
    Raise NotInvertibleError if gcd(a, n) != 1.
    """
    if n <= 0:
        raise ValueError("modulus must be positive")
    g, x, _ = egcd(a, n)
    if g != 1:
        raise NotInvertibleError(f"{a} has no inverse modulo {n} (gcd={g})")
    return x % n

def modexp(base: int, exp: int, mod: int) -> int:
    """
    Binary exponentiation: compute base**exp mod mod.
    (Non-negative exp; positive modulus.)
    """
    if mod <= 0:
        raise ValueError("modulus must be positive")
    if exp < 0:
        raise ValueError("negative exponents not supported")
    
    if mod == 1:
        return 0
    
    result = 1 % mod
    b = base % mod
    e = exp
    while e:
        if e & 1:
            result = (result * b) % mod
        b = (b * b) % mod
        e >>= 1
    return result