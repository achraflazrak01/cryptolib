import pytest
from cryptolib.asymmetric.toy.rsa_toy import keygen, encrypt_int, decrypt_int, RSAPublicKey, RSAPrivateKey
from cryptolib.asymmetric.toy.dh_modp import public_from_secret, shared_secret
from cryptolib.exceptions import InvalidKeyError, ValidationError

def test_rsa_round_trip_and_d_value():
    # Classic small primes
    p, q, e = 61, 53, 17
    pub, prv = keygen(p, q, e)
    assert isinstance(pub, RSAPublicKey) and isinstance(prv, RSAPrivateKey)
    # Known textbook phi and d for these parameters
    # phi = (61-1)*(53-1) = 3120; d = e^{-1} mod phi = 2753
    assert prv.d == 2753
    # Round-trip with a small integer message
    m = 65  # must be < n
    c = encrypt_int(m, pub)
    m2 = decrypt_int(c, prv)
    assert m2 == m

def test_rsa_invalid_e_raises():
    p, q = 61, 53
    e = 12  # gcd(12,3120)!=1
    with pytest.raises(InvalidKeyError):
        keygen(p, q, e)

def test_rsa_message_range_checks():
    pub, prv = keygen(61, 53, 17)
    with pytest.raises(ValidationError):
        encrypt_int(-1, pub)
    with pytest.raises(ValidationError):
        encrypt_int(pub.n, pub)  # must be < n
    c = encrypt_int(1, pub)
    with pytest.raises(ValidationError):
        decrypt_int(prv.n, prv)  # invalid ciphertext range
    assert decrypt_int(c, prv) == 1

def test_dh_shared_secret_matches():
    # small toy group
    p, g = 23, 5
    a, b = 6, 15
    A = public_from_secret(g, p, a)
    B = public_from_secret(g, p, b)
    s1 = shared_secret(B, p, a)
    s2 = shared_secret(A, p, b)
    assert s1 == s2
    # Range checks
    with pytest.raises(ValidationError):
        public_from_secret(1, p, a)  # g must be >1 and <p
    with pytest.raises(ValidationError):
        shared_secret(p, p, a)       # peer public must be < p
