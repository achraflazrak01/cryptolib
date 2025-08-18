import os
from cryptolib.experiments.ufcma import forge_rsa_textbook_demo, try_forge_ed25519_demo
from cryptolib.asymmetric.wrappers.sig import ed25519_keygen, ed25519_sign, ed25519_verify

def test_textbook_rsa_forgery_succeeds():
    assert forge_rsa_textbook_demo() is True

def test_ed25519_sign_verify_and_random_forgery_fails():
    sk, pk = ed25519_keygen()
    msg = b"hello world"
    sig = ed25519_sign(sk, msg)
    assert ed25519_verify(pk, msg, sig) is True

    # tamper the signature -> must fail
    bad = bytearray(sig); bad[0] ^= 0x01
    assert ed25519_verify(pk, msg, bytes(bad)) is False

    # naive random forgery should also fail
    assert try_forge_ed25519_demo() is False
