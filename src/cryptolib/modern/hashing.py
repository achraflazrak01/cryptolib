import hashlib

def md5_hexdigest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

def sha256_hexdigest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
