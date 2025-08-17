def has_repeated_blocks(ciphertext: bytes, block: int = 16) -> bool:
    """Detect ECB pattern leak: any repeated block appears identical."""
    blocks = [ciphertext[i: i + block] for i in range(0, len(ciphertext), block)]
    return len(set(blocks)) < len(blocks)
