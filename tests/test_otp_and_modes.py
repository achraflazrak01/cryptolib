import os, pytest
from cryptography.exceptions import InvalidTag

from cryptolib.classical.otp import encrypt as otp_enc, decrypt as otp_dec, xor_bytes
from cryptolib.cryptanalysis.otp_twotime import c1_xor_c2, recover_with_crib
from cryptolib.cryptanalysis.ecb_pattern import has_repeated_blocks
from cryptolib.cryptanalysis.ctr_nonce_reuse import aes_ctr_encrypt, xor_plaintexts_from_reuse
from cryptolib.modern.aead.aes_gcm import encrypt as gcm_enc, decrypt as gcm_dec
from cryptolib.exceptions import ValidationError

def test_otp_round_trip_true_length():
    m = b"THIS IS A SECRET"
    k = os.urandom(len(m))
    c = otp_enc(m, k)
    assert otp_dec(c, k) == m

def test_otp_length_mismatch_raises():
    with pytest.raises(ValidationError):
        otp_enc(b"A", b"")

def test_two_time_pad_crib_attack():
    m1 = b"ATTACK AT DAWN"
    m2 = b"ATTACK AT DUSK"
    k  = os.urandom(len(m1))
    c1 = otp_enc(m1, k)
    c2 = otp_enc(m2, k)
    # attacker computes m1⊕m2
    x = c1_xor_c2(c1, c2)
    # knowing crib " ATTACK " at pos 0 recovers the other segment
    rec = recover_with_crib(c1, c2, b"ATTACK", 0)
    assert rec == b"ATTACK"[:len(rec)]

def test_ecb_repeated_blocks_detected():
    # Make a plaintext with repeated 16-byte blocks
    block = b"A" * 16
    pt = block * 4
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = os.urandom(16)
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    ct = ecb.update(pt) + ecb.finalize()
    assert has_repeated_blocks(ct, 16) is True

def test_ctr_nonce_reuse_implies_plaintext_xor_equal():
    key = os.urandom(16)
    nonce = os.urandom(16)  # CTR nonce is 16 bytes for AES block size
    m1 = b"THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    m2 = b"PACK MY BOX WITH FIVE DOZEN LIQUOR JUGS    "
    c1 = aes_ctr_encrypt(key, nonce, m1)
    c2 = aes_ctr_encrypt(key, nonce, m2)
    assert xor_plaintexts_from_reuse(c1, c2) == xor_bytes(m1, m2)

def test_aes_gcm_round_trip_and_tamper_detection():
    key = os.urandom(32)  # AES-256
    m = b"authenticated encryption"
    aad = b"context"
    nonce, ct = gcm_enc(key, m, aad)
    p = gcm_dec(key, nonce, ct, aad)
    assert p == m

    # flip one byte -> should raise InvalidTag
    bad = bytearray(ct)
    bad[0] ^= 0x01
    with pytest.raises(InvalidTag):
        gcm_dec(key, nonce, bytes(bad), aad)
