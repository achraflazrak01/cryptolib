# Kasiski + (fallback) IOC + per-column chi-square to recover key & plaintext
from collections import defaultdict
from math import gcd
from typing import List, Tuple
from cryptolib.exceptions import ValidationError

ALPH = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
A0 = ord("A")

# English letter frequencies (%) — same table used for Caesar attack
FREQ_EN = [
    8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153,
    0.772, 4.025, 2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056,
    2.758, 0.978, 2.360, 0.150, 1.974, 0.074,
]

def _clean(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z")

def _chisq(s: str) -> float:
    n = len(s)
    if n == 0:
        return float("inf")
    obs = [0] * 26
    for ch in s:
        obs[ord(ch) - A0] += 1
    score = 0.0
    for i in range(26):
        exp = n * (FREQ_EN[i] / 100.0)
        if exp <= 1e-12:
            continue
        diff = obs[i] - exp
        score += (diff * diff) / exp
    return score

def _shift_clean(s: str, k: int) -> str:
    # shift already-clean A-Z string by k (mod 26)
    return "".join(ALPH[(ord(c) - A0 + k) % 26] for c in s)

def kasiski_lengths(cipher: str, min_len: int = 3, max_len: int = 5) -> List[int]:
    """Return candidate key lengths from Kasiski (divisors of repeated trigram distances)."""
    s = _clean(cipher)
    pos = defaultdict(list)
    for L in range(min_len, max_len + 1):
        for i in range(len(s) - L + 1):
            pos[s[i: i + L]].append(i)
    dists: List[int] = []
    for inds in pos.values():
        if len(inds) >= 2:
            for i in range(1, len(inds)):
                dists.append(inds[i] - inds[i - 1])
                
    if not dists:
        return []
    g = 0
    for d in dists:
        g = gcd(g, d)
    # return all divisors of g, filtered to sensible sizes
    return [k for k in range(1, g + 1) if g % k == 0]

def _best_shift_for_column(col: str) -> int:
    """Return the shift k (0..25) that makes this column most like English."""
    best_k, best_score = 0, float("inf")
    for k in range(26):
        sc = _chisq(_shift_clean(col, -k))  # decrypt with shift k, score
        if sc < best_score:
            best_k, best_score = k, sc
    return best_k

def _decrypt_with_shifts(text: str, shifts: List[int]) -> str:
    """Decrypt whole text using periodic shifts (index by i % len(shifts))."""
    m = len(shifts)
    return "".join(ALPH[(ord(ch) - A0 - shifts[i % m]) % 26] for i, ch in enumerate(text))

def _compress_repeating_shifts(shifts: List[int]) -> List[int]:
    """Shrink repeating keys: [M,A,G,N,U,M,M,A,G,N,U,M] -> [M,A,G,N,U,M]."""
    L = len(shifts)
    for t in range(1, L + 1):
        if L % t == 0 and all(shifts[i] == shifts[i % t] for i in range(L)):
            return shifts[:t]
    return shifts

def crack(ciphertext: str) -> Tuple[str, str]:
    """
    Recover (key, plaintext) by testing candidate periods.
    Picks the absolute best chi-square plaintext. Raises ValidationError if no A–Z letters.
    """
    s = _clean(ciphertext)
    if not s:
        raise ValidationError("No A–Z letters in ciphertext to analyze")

    # candidate periods: small ones first, then Kasiski hints (dedup)
    periods: List[int] = list(range(1, min(12, len(s)) + 1))
    for m in kasiski_lengths(s):
        if 1 <= m <= len(s) and m not in periods:
            periods.append(m)

    best_score, best_shifts, best_plain = float("inf"), [], ""

    for m in periods:
        cols = [s[r::m] for r in range(m)]
        shifts = [_best_shift_for_column(col) for col in cols]
        pt = _decrypt_with_shifts(s, shifts)
        sc = _chisq(pt)
        if sc < best_score:
            best_score, best_shifts, best_plain = sc, shifts, pt

    best_shifts = _compress_repeating_shifts(best_shifts)
    key = "".join(ALPH[k] for k in best_shifts)
    return key, best_plain
