import os
from dataclasses import dataclass
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptolib.cryptanalysis.ecb_pattern import has_repeated_blocks
from cryptolib.modern.aead.aes_gcm import encrypt as gcm_encrypt

@dataclass(frozen=True)
class CPAResult:
    wins: int
    trials: int
    @property
    def rate(self) -> float:
        return self.wins / self.trials if self.trials else 0.0
    
def _randbit() -> int:
    return os.urandom(1)[0] & 1

def _ecb_encrypt(key: bytes, pt: bytes) -> bytes:
    enc = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return enc.update(pt) + enc.finalize()

def run_trial_ecb() -> int:
    """
    One IND-CPA trial for AES-ECB.
    Attacker guesses 'repeated-block' message if ciphertext has repeated 16B blocks.
    Returns 1 if attacker wins; else 0.
    """
    key = os.urandom(16)
    m0 = (b"A" * 16) * 4            # repeated block message
    m1 = os.urandom(len(m0))        # random-looking message
    b = _randbit()
    c =  _ecb_encrypt(key, m0 if b == 0 else m1)
    guess = 0 if has_repeated_blocks(c, 16) else 1
    return int(guess == b)

def run_trial_gcm() -> int:
    """
    One IND-CPA trial for AES-GCM (randomized AEAD).
    Same attacker as ECB (repeated-block check) should perform ~random (~0.5).
    Returns 1 if attacker wins; else 0.
    """
    key = os.urandom(16)
    m0 = (b"A" * 16) * 4
    m1 = os.urandom(len(m0))
    b = _randbit()
    _, ct = gcm_encrypt(key, m0 if b == 0 else m1, None)  # ct includes the 16B tag at the end
    body = ct[:-16] if len(ct) >= 16 else ct
    guess = 0 if has_repeated_blocks(body, 16) else 1
    return int(guess == b)

def run_trial_ctr_fixed_nonce() -> int:
    """(Implemented on Day 3)"""
    raise NotImplementedError("Week-2 Day 3: implement CTR fixed-nonce CPA trial")
