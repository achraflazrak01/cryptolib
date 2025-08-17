from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_ctr_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> bytes:
    """
    AES-CTR (demo only; not authenticated). Nonce length must be 16 bytes.
    """
    if len(nonce) != 16:
        raise ValueError("CTR nonce must be 16 bytes for AES block size")
    encryptor = Cipher(algorithms.AES(key), modes.CTR(nonce)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def xor_plaintexts_from_reuse(c1: bytes, c2: bytes) -> bytes:
    """
    For reused (key, nonce) in CTR: c1⊕c2 = m1⊕m2 (same as OTP reuse).
    """
    from cryptolib.classical.otp import xor_bytes
    return xor_bytes(c1, c2)
