from cryptolib.mathutils.number import modexp
from cryptolib.exceptions import ValidationError

def public_from_secret(g: int, p: int, a: int) -> int:
    """
    Return A = g ^ a mod p. Requires 1 < g < p and 1 <= a < p.
    (We don't primality-check p here: this is an educational toy.)
    """
    if not (1 < g < p):
        raise ValidationError("Require 1 < g < p")
    if not (1 <= a < p):
        raise ValidationError("Require 1 <= secret < p")
    return modexp(g, a, p)

def shared_secret(peer_public: int, p: int, a: int) -> int:
    """
    Returns s = (peer_public)^a mod p. Requires values in [1, p - 1].
    """
    if not (1 <= peer_public < p):
        raise ValidationError("peer public must be in [1, p - 1]")
    if not (1 <= a < p):
        raise ValidationError("Require 1 <= secret < p")
    return modexp(peer_public, a, p)
