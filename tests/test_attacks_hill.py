from cryptolib.classical.hill.hill2 import encrypt
from cryptolib.cryptanalysis.hill_attack import recover_key

def test_hill_known_plaintext_attack_recovers_key():
    K = [[3, 3], [2, 5]]  # invertible: det = 9, gcd(9,26)=1
    # choose two independent plaintext pairs so P is invertible mod 26
    p1, p2 = "HE", "LP"  # P = [[7,11],[4,15]] -> det = 61 ≡ 9 (invertible)
    c1 = encrypt(p1, K)
    c2 = encrypt(p2, K)

    K2 = recover_key(p1, p2, c1, c2)
    # re-encrypt p1,p2 with recovered key should match c1,c2
    assert encrypt(p1, K2) == c1
    assert encrypt(p2, K2) == c2
    # and K2 equals K modulo 26 (element-wise)
    for r in range(2):
        for c in range(2):
            assert K2[r][c] % 26 == K[r][c] % 26
