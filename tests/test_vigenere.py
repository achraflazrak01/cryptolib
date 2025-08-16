from cryptolib.classical.vigenere import encrypt, decrypt
from cryptolib.exceptions import ValidationError
import pytest

def test_known_vector_lemon():
    # Classic example: ATTACKATDAWN + LEMON -> LXFOPVEFRNHR
    assert encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert decrypt("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"
    
def test_round_trip_with_noise():
    msg = "Meet me @ the park, at eleven am."
    key = "LEMON"
    c = encrypt(msg, key)
    p = decrypt(c, key)
    assert p == "MEETMETHEPARKATELEVENAM"  # A–Z only

def test_empty_or_bad_key_raises():
    with pytest.raises(ValidationError):
        encrypt("HELLO", "")
    with pytest.raises(ValidationError):
        decrypt("HELLO", "   ")