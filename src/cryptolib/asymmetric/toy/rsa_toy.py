from dataclasses import dataclass
from math import gcd, isqrt
from cryptolib.mathutils.number import modinv, modexp
from cryptolib.exceptions import InvalidKeyError, ValidationError

@dataclass(frozen=True)
class RSAPublicKey:
    n: int  # modulus
    e: int  # public exponent

@dataclass(frozen=True)
class RSAPrivateKey:
    n: int  # modulus
    d: int  # private exponent

def _is_small_prime(n: int) -> bool:
    if n < 2: return False
    if n % 2 == 0: return n == 2
    r = isqrt(n)
    f = 3
    while f <= r:
        if n % f == 0:
            return False
        f += 2
    return True

def keygen(p: int, q: int, e: int) -> tuple[RSAPublicKey, RSAPrivateKey]:
    """
    Toy RSA keygen (educational). Requires prime p,q (small ok) and gcd(e,phi)=1.
    Raises InvalidKeyError on bad inputs.
    """
    if p == q:
        raise InvalidKeyError("p and q must be distinct primes")
    if not _is_small_prime(p) or not _is_small_prime(q):
        raise InvalidKeyError("p and q must be prime (toy RSA)")
    n = p * q
    phi = (p - 1) * (q - 1)
    if e <= 1 or e >= phi or gcd(e, phi) != 1:
        raise InvalidKeyError("public exponent e must satisfy 1 < e < phi and gcd(e, phi) = 1")
    d = modinv(e, phi)
    return RSAPublicKey(n=n, e=e), RSAPrivateKey(n=n, d=d)

def encrypt_int(m: int, pub: RSAPublicKey) -> int:
    """RSA encryption on integers: c = m^e mod n. Requires 0 <= m < n."""
    if not (0 <= m < pub.n):
        raise ValidationError("message integer must satisfy 0 <= m < n")
    return modexp(m, pub.e, pub.n)

def decrypt_int(c: int, prv: RSAPrivateKey) -> int:
    """RSA decryption on integers: m = c^d mod n. Requires 0 <= c < n."""
    if not (0 <= c < prv.n):
        raise ValidationError("cipher integer must satisfy 0 <= c < n")
    return modexp(c, prv.d, prv.n)
