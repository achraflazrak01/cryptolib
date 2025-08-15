from typing import Tuple
from cryptolib.exceptions import ValidationError

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A0 = ord("A")

# English letter frequencies (%) — classic table
FREQ_EN = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
]

def _clean(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z")

def _shift(s: str, k: int) -> str:
    return "".join(ALPH[(ord(c) - A0 + k) % 26] for c in s)

def _chisq(s: str) -> float:
    """Chi-square score vs English. Lower = closer to English distribution."""
    n = len(s)
    if n == 0:
        return float("inf")
    obs = [0] * 26
    for ch in s:
        obs[ord(ch) - A0] += 1
    score = 0.0
    for i in range(26):
        expected = n * (FREQ_EN[i] / 100.0)
        # expected never 0 with this table, but keep guard:
        if expected <= 1e-12:
            continue
        diff = obs[i] - expected
        score += (diff * diff) / expected
    return score

def crack(ciphertext: str) -> Tuple[int, str]:
    """
    Return (best_shift, plaintext_guess) by minimizing chi-square
    over all 26 possible shifts.
    """
    c = _clean(ciphertext)
    if not c:
        raise ValidationError("No A–Z letters in ciphertext to analyze")
    best_k, best_score, best_pt = 0, float("inf"), ""
    for k in range(26):
        pt = _shift(c, -k) # try decrypting with shift k
        s = _chisq(pt)
        if s < best_score:
            best_k, best_score, best_pt = k, s, pt
    return best_k, best_pt
