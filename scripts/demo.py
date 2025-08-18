# scripts/demo.py
from cryptolib.classical.caesar import encrypt as c_enc, decrypt as c_dec
from cryptolib.cryptanalysis.caesar_attack import crack as c_crack

from cryptolib.classical.vigenere import encrypt as v_enc, decrypt as v_dec
from cryptolib.cryptanalysis.vigenere_attack import crack as v_crack

from cryptolib.classical.playfair.playfair import encrypt as pf_enc, decrypt as pf_dec
from cryptolib.classical.playfair.helpers import prepare_pairs

from cryptolib.classical.hill.hill2 import encrypt as h_enc, decrypt as h_dec
from cryptolib.cryptanalysis.hill_attack import recover_key as hill_recover

from cryptolib.classical.otp import encrypt as otp, xor_bytes
from cryptolib.cryptanalysis.ecb_pattern import has_repeated_blocks
from cryptolib.cryptanalysis.ctr_nonce_reuse import aes_ctr_encrypt

from cryptolib.modern.aead.aes_gcm import encrypt as gcm_enc, decrypt as gcm_dec
from cryptography.exceptions import InvalidTag

from cryptolib.asymmetric.toy.rsa_toy import keygen, encrypt_int, decrypt_int
from cryptolib.asymmetric.toy.dh_modp import public_from_secret, shared_secret

import os

def sep(title): print("\n" + "=" * 10, title, "=" * 10)

def main():
    # 1) Classical + attacks
    sep("Caesar")
    msg = "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG"
    k = 19
    c = c_enc(msg, k)
    print("cipher:", c)
    k2, pt = c_crack(c)
    print("crack shift:", k2, "pt[:24]:", pt[:24])

    sep("Vigenere")
    EN_TEXT = (
        "Alice was beginning to get very tired of sitting by her sister on the bank, "
        "and of having nothing to do: once or twice she had peeped into the book her "
        "sister was reading, but it had no pictures or conversations in it, and what "
        "is the use of a book, thought Alice without pictures or conversation? "
    ) * 3  # repeat to give the attack enough signal
    vig_key = "MAGNUM"
    vc = v_enc(EN_TEXT, vig_key)
    vkey_guess, vpt = v_crack(vc)
    print("cipher[:24]:", vc[:24])
    print("key_guess:", vkey_guess, "pt[:24]:", vpt[:24])

    sep("Playfair")
    pf_key = "MONARCHY"
    c = pf_enc("Hide the gold in the tree stump", pf_key)
    p = pf_dec(c, pf_key)
    print("cipher:", c[:24], "...")
    print("plaintext digraphs match prepare_pairs:", p == "".join(a+b for a,b in prepare_pairs("Hide the gold in the tree stump")))

    sep("Hill 2x2")
    K = [[3, 3], [2, 5]]
    c = h_enc("SECRETMESSAGE", K)
    p = h_dec(c, K)
    print("cipher:", c[:12], "...", "roundtrip ok:", p.startswith("SECRETMESSAGE".upper()[:12]))
    # Known-plaintext recover
    p1, p2="HE", "LP"
    c1 = h_enc(p1, K)
    c2 = h_enc(p2, K)
    K2 = hill_recover(p1, p2, c1, c2)
    print("recovered K == K mod 26:", all(K2[i][j] % 26 == K[i][j] % 26 for i in range(2) for j in range(2)))

    # 2) Misuse + modern
    sep("OTP two-time pad")
    m1 = b"ATTACK AT DAWN"
    m2 = b"ATTACK AT DUSK"
    k = os.urandom(len(m1))
    c1 = otp(m1, k)
    c2 = otp(m2, k)
    print("c1 ^ c2 == m1 ^ m2:", xor_bytes(c1, c2) == xor_bytes(m1, m2))

    sep("ECB pattern leak")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = os.urandom(16)
    pt = (b"A" * 16) * 4
    ct = Cipher(algorithms.AES(key), modes.ECB()).encryptor().update(pt)
    print("repeated blocks detected:", has_repeated_blocks(ct, 16))

    sep("CTR nonce reuse")
    key = os.urandom(16); nonce = os.urandom(16)
    m1 = b"The quick brown fox jumps over the lazy dog"
    m2 = b"Pack my box with five dozen liquor jugs    "
    c1 = aes_ctr_encrypt(key, nonce, m1)
    c2 = aes_ctr_encrypt(key, nonce, m2)
    print("c1 ^ c2 == m1 ^ m2:", xor_bytes(c1, c2) == xor_bytes(m1, m2))

    sep("AES-GCM tamper detection")
    key = os.urandom(16)
    nonce, ct = gcm_enc(key, b"authenticated encryption", b"context")
    bad = bytearray(ct)
    bad[0] ^= 1
    try:
        gcm_dec(key, nonce, bytes(bad), b"context")
        print("tamper undetected? (should not happen)")
    except InvalidTag:
        print("InvalidTag caught (good)")

    # 3) Toy public-key
    sep("RSA toy")
    pub, prv = keygen(61, 53, 17)
    m = 65
    c = encrypt_int(m, pub)
    m2 = decrypt_int(c, prv)
    print("roundtrip m == m2:", m == m2)

    sep("Diffie–Hellman toy")
    p, g = 23, 5 
    a, b = 6, 15
    A = public_from_secret(g, p, a)
    B = public_from_secret(g, p, b)
    s1 = shared_secret(B, p, a) 
    s2 = shared_secret(A, p, b)
    print("shared secrets equal:", s1 == s2)

    # 4) Mini CPA/CCA trials (quick estimate)
    sep("CPA/CCA quick rates")
    from cryptolib.experiments.cpa import run_trial_ecb, run_trial_gcm, run_trial_ctr_fixed_nonce
    from cryptolib.experiments.cca import run_trial_cca_ctr_fixed_nonce, run_trial_cca_gcm
    def rate(trials, fn):
        return sum(fn() for _ in range(trials)) / trials
    print(f"ECB CPA rate ~>0.9: {rate(60, run_trial_ecb):.2f}")
    print(f"GCM CPA rate ~0.5 : {rate(120, run_trial_gcm):.2f}")
    print(f"CTR(fixed) CPA ~1 : {rate(30, run_trial_ctr_fixed_nonce):.2f}")
    print(f"CCA CTR(fixed) ~1 : {rate(20, run_trial_cca_ctr_fixed_nonce):.2f}")
    print(f"CCA GCM ~0.5      : {rate(120, run_trial_cca_gcm):.2f}")

if __name__ == "__main__":
    main()
