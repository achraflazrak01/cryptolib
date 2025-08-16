from cryptolib.classical.vigenere import encrypt, decrypt
from cryptolib.cryptanalysis.vigenere_attack import crack
from cryptolib.classical.vigenere import _clean_text as clean  # or your own clean()

EN_TEXT = (
    "Alice was beginning to get very tired of sitting by her sister on the bank, "
    "and of having nothing to do: once or twice she had peeped into the book her "
    "sister was reading, but it had no pictures or conversations in it, 'and what "
    "is the use of a book,' thought Alice 'without pictures or conversation?' "
) * 3  # repeat to make it long


def test_vigenere_crack_recovers_plaintext_and_roundtrip():
    key = "MAGNUM"
    c = encrypt(EN_TEXT, key)
    got_key, pt = crack(c)

    # 1) Round-trip correctness: recovered (key, pt) re-encrypts to the ciphertext
    assert encrypt(pt, got_key) == c

    # 2) Key canonicalization: handle multiple-of-period keys (e.g., 12 vs 6)
    # compress repeating keys like 'MAGNUMMAGNUM' → 'MAGNUM'
    def compress(k: str) -> str:
        for t in range(1, len(k) + 1):
            if len(k) % t == 0 and all(k[i] == k[i % t] for i in range(len(k))):
                return k[:t]
        return k

    assert compress(got_key) == "MAGNUM"
