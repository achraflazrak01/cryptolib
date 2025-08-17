from cryptolib.exceptions import ValidationError

def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValidationError("xor_bytes requires equal lengths")
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """
    True OTP: key length must equal plaintext length.
    Returns ciphertext = plaintext XOR key.
    """
    if len(plaintext) != len(key):
        raise ValidationError("OTP key length must equal plaintext length")
    return xor_bytes(plaintext, key)

def decrypt(plaintext: bytes, key: bytes) -> bytes:
    if len(plaintext) != len(key):
        raise ValidationError("OTP key length must equal plaintext length")
    return xor_bytes(plaintext, key)
