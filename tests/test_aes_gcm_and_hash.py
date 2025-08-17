from cryptolib.modern.hashing import md5_hexdigest, sha256_hexdigest
from cryptolib.modern.aead.aes_gcm import encrypt as gcm_enc, decrypt as gcm_dec
import os

def test_hash_vectors():
    assert md5_hexdigest(b"abc") == "900150983cd24fb0d6963f7d28e17f72"
    assert sha256_hexdigest(b"abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

def test_gcm_basic():
    key = os.urandom(16)
    m = b"hello"
    nonce, ct = gcm_enc(key, m, None)
    assert gcm_dec(key, nonce, ct, None) == m
