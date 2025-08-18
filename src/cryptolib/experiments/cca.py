import os
from cryptolib.cryptanalysis.ctr_nonce_reuse import aes_ctr_encrypt
from cryptolib.modern.aead.aes_gcm import encrypt as gcm_encrypt, decrypt as gcm_decrypt
from cryptography.exceptions import InvalidTag

def run_trial_cca_ctr_fixed_nonce() -> int:
    """
    Chosen-ciphertext attack on AES-CTR with a FIXED nonce.
    Strategy: flip one byte in the challenge ciphertext (c→c'), query the
    decryption oracle on c' (allowed since c'!=c). In CTR, flipping a bit in c
    flips the same bit in the plaintext → we learn which message was used.
    Returns 1 if attacker wins; else 0 (≈1.0 success).
    """
    key = os.urandom(16)
    nonce = os.urandom(16)
    
    # Encryption/decryption oracles (same stream for CTR); forbidden only on EXACT 'c'
    def Enc(m: bytes) -> bytes:
        return aes_ctr_encrypt(key, nonce, m)
    def Dec(c: bytes) -> bytes:
        return aes_ctr_encrypt(key, nonce, c)
    
    # Choose messages that are easy to distinguish by a 1-bit flip
    m0 = bytes([0x00]) * 64
    m1 = bytes([0xFF]) * 64
    
    b = os.urandom(1)[0] & 1
    c = Enc(m0 if b == 0 else m1)
    
    # Forge a different ciphertext c' by flipping LSB of the first byte
    c_prime = bytearray(c)
    c_prime[0] ^= 0x01
    c_prime = bytes(c_prime)
    
    # Ask the decryption oracle on c' (allowed: c' != c)
    m_prime = Dec(c_prime)
    
    # If original was m0=0x00.., then m'[0]==0x01; if m1=0xFF.., then m'[0]==0xFE
    guess = 0 if m_prime[0] == 0x01 else 1
    return int(guess == b)

def run_trial_cca_gcm() -> int:
    """
    CCA trial against AES-GCM. Any modification to (nonce,ciphertext,tag)
    causes decryption to raise InvalidTag, so the oracle reveals nothing.
    Attacker must guess randomly → success ~0.5.
    """
    key = os.urandom(16)
    m0 = bytes([0x00]) * 64
    m1 = bytes([0xFF]) * 64
    b = os.urandom(1)[0] & 1
    nonce, c = gcm_encrypt(key, m0 if b == 0 else m1, None)
    
    # Tamper one byte (not equal to the challenge anymore)
    bad = bytearray(c)
    bad[0] ^= 0x01
    c_prime = bytes(bad)
    
    # Description oracle (same key, same nonce); returns Nonce on tag failure
    def Dec(n: bytes, ct: bytes):
        try:
            return gcm_decrypt(key, n, ct, None)
        except InvalidTag:
            return None

    _ = Dec(nonce, c_prime)  # always None; provides no info
    guess = os.urandom(1)[0] & 1
    return int(guess == b)
