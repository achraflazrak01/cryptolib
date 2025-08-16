from cryptolib.classical.hill.helpers import inv2x2_mod26

A0 = ord("A")

def _v(pair: str) -> list[int]:
    return [ord(pair[0]) - A0, ord(pair[1]) - A0]

def _mat_from_pairs(p1: str, p2: str) -> list[list[int]]:
    x1, y1 = _v(p1)
    x2, y2 = _v(p2)
    # columns are the two vectors
    return [[x1, x2], [y1, y2]]

def _mat_mul(A: list[list[int]], B: list[list[int]]) -> list[list[int]]:
    return [
        [ (A[0][0]*B[0][0] + A[0][1]*B[1][0]) % 26,
          (A[0][0]*B[0][1] + A[0][1]*B[1][1]) % 26 ],
        [ (A[1][0]*B[0][0] + A[1][1]*B[1][0]) % 26,
          (A[1][0]*B[0][1] + A[1][1]*B[1][1]) % 26 ],
    ]

def recover_key(p1: str, p2: str, c1: str, c2: str) -> list[list[int]]:
    """
    Given two plaintext digraphs (p1, p2) and their ciphertext digraphs (c1, c2).
    recover K such that C = K * P (mod 26), i.e. K = C * P^{-1} (mod 26).
    """
    P = _mat_from_pairs(p1, p2)
    C = _mat_from_pairs(c1, c2)
    Pinv = inv2x2_mod26(P)
    return _mat_mul(C, Pinv)
