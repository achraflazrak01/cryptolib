from cryptolib.classical.caesar import encrypt
from cryptolib.cryptanalysis.caesar_attack import crack

EN_TEXT = (
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
    "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG "
).strip()

def test_caesar_crack_recovers_key():
    for k in (1, 3, 7, 13, 19, 25):
        c = encrypt(EN_TEXT, k)
        got_k, pt  = crack(c)
        assert got_k == (k % 26)
        # plaintext is normalized A-Z
        assert pt.startswith("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG")
        
