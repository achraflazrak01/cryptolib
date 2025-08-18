from cryptolib.asymmetric.toy.rsa_toy import keygen, encrypt_int # encrypt_int = pow(sig, e, n)
from cryptolib.mathutils.number import modexp

def forge_rsa_textbook_demo() -> bool:
    """
    Multiplicative forgery on textbook RSA signatures.
    Use small, known-safe toy parameters (p=61, q=53, e=17).
    Sign(m) = m^d mod n; Verify(sig,m): sig^e ≡ m (mod n).
    Forge: s3 = s1*s2 mod n is signature of m3 = m1*m2 mod n.
    Returns True if the forged signature verifies for a *new* message m3.
    """
    # toy RSA key
    p, q, e  = 61, 53, 17
    pub, prv = keygen(p, q, e)
    n = pub.n
    
    # Signing oracle (textbook): s = m ^ d mod n
    def sign(m: int) -> int:
        return modexp(m, prv.d, n)
    
    # Choose two small messages(nonzero, < n) with distinct product modulo n
    m1, m2 = 2, 3
    s1 = sign(m1)
    s2 = sign(m2)
    
    # Forge
    m3 = (m1 * m2) % n
    s3 = (s1 * s2) % n
    
    # Verify using public exponent e: s3 ^ e ?= m3 (mod n)
    ok = (encrypt_int(s3, pub) == m3) # encrypt_int(x, pub) = x ^ e mod n
    
    # ensure it's not trivially reusing a queried message
    return ok and m3 not in (m1, m2)

def try_forge_ed25519_demo() -> bool:
    """
    Naive 'random' forgery attempt on Ed25519 should fail.
    Returns True iff a random signature verifies (expected: False).
    """
    import os
    from cryptolib.asymmetric.wrappers.sig import ed25519_keygen, ed25519_verify
    sk, pk = ed25519_keygen()
    msg = b"educational cryptography"
    fake_sig = os.urandom(64)  # Ed25519 signatures are 64 bytes
    return ed25519_verify(pk, msg, fake_sig)
