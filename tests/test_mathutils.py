import pytest
from cryptolib.mathutils.number import egcd, modinv, modexp
from cryptolib.exceptions import NotInvertibleError

def test_egcd_invariant():
    a, b = 99, 78
    g, x, y = egcd(a, b)
    assert g == 3
    assert a * x + b * y == g # Bezout identity holds

def test_modinv_basic_and_failure():
    assert modinv(7, 26) == 15
    with pytest.raises(NotInvertibleError):
        modinv(2, 26)
        
def test_modexp_basics():
    assert modexp(13, 11, 19) == 2       # sanity vector
    assert modexp(123456789, 0, 97) == 1 # a^0 = 1 (mod m)
    # consistency with Python's pow(a, e, m) for a few values
    for (a, e, m) in [(5, 117, 19), (42, 73, 101), (-7, 9, 26)]:
        assert modexp(a, e, m) == pow(a, e, m)