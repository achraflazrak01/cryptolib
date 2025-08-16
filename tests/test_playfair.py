import pytest
from cryptolib.classical.playfair.helpers import build_square, prepare_pairs
from cryptolib.classical.playfair.playfair import encrypt, decrypt
from cryptolib.exceptions import ValidationError

def clean(s: str) -> str:
    return "".join(ch for ch in s.upper() if "A" <= ch <= "Z").replace("J", "I")

def test_build_square_has_25_unique_no_J():
    sq = build_square("MONARCHY")
    assert len(sq) == 25
    assert len(set(sq)) == 25
    assert "J" not in sq
    for ch in sq:
        assert "A" <= ch <= "Z" and ch != "J"

def test_prepare_pairs_inserts_X_and_pads():
    assert "".join(a + b for a, b in prepare_pairs("BALLOON")) == "BALXLOON"
    assert "".join(a + b for a, b in prepare_pairs("HELLO")) == "HELXLO"
    assert "".join(a + b for a, b in prepare_pairs("JAM")) == "IAMX"  # J->I, pad X

def test_round_trip_keeps_inserted_X():
    key = "MONARCHY"
    msg = "Hide the gold in the tree stump"
    c = encrypt(msg, key)
    p = decrypt(c, key)
    expected = "".join(a + b for a, b in prepare_pairs(msg))
    assert p == expected

def test_encrypt_decrypt_symmetry_many():
    key = "PLAYFAIREXAMPLE"
    texts = ["ATTACKATDAWN", "BALLOON", "MEETMEATNINE", "X", "ABC", "JIGSAW PUZZLE!!"]
    for m in texts:
        c = encrypt(m, key)
        p = decrypt(c, key)
        expected = "".join(a + b for a, b in prepare_pairs(m))
        assert p == expected

def test_empty_key_raises():
    with pytest.raises(ValidationError):
        encrypt("HELLO", "")
