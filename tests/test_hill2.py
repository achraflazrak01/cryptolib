import pytest
from cryptolib.classical.hill.hill2 import encrypt, decrypt
from cryptolib.classical.hill.helpers import mod26_det, is_invertible_mod26
from cryptolib.exceptions import InvalidKeyError

def clean(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z")

def test_known_vector_hi_to_tc_and_back():
    K = [[3, 3], [2, 5]]
    assert encrypt("HI", K) == "TC"
    assert decrypt("TC", K) == "HI"

def test_round_trip_and_padding():
    K = [[3, 3], [2, 5]]
    msg = "SECRETMESSAGE"
    c = encrypt(msg, K)
    p = decrypt(c, K)
    expect = clean(msg)
    if len(expect) % 2 == 1:
        expect += "X"
    assert p == expect

def test_reject_noninvertible_key():
    bad = [[2, 4], [2, 6]]  # det = 2*6 - 4*2 = 4 ≡ 4 (gcd(4,26)=2) -> not invertible
    assert mod26_det(bad) % 26 == 4
    assert not is_invertible_mod26(bad)
    with pytest.raises(InvalidKeyError):
        encrypt("TEST", bad)
