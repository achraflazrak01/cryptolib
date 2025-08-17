from cryptolib.classical.otp import xor_bytes

def c1_xor_c2(c1: bytes, c2: bytes) -> bytes:
    """Return m1⊕m2 when the *same OTP key* was reused (c1⊕c2 = m1⊕m2)."""
    return xor_bytes(c1, c2)

def recover_with_crib(c1: bytes, c2: bytes, crib: bytes, pos: int) -> bytes:
    """
    If you know m1 segment at position pos (crib), recover m2 segment there:
    m2[pos..] = (c1⊕c2)[pos..] ⊕ crib
    """
    x = c1_xor_c2(c1, c2)
    return xor_bytes(x[pos: pos + len(crib)], crib)
