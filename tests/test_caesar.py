from cryptolib.classical.caesar import encrypt, decrypt

def test_round_trip_basic():
    msg = "Hello, World!"
    for k in (0, 1, 3, 13, 25, -4, 52):
        c = encrypt(msg, k)
        p = decrypt(c, k)
        assert p == "HELLOWORLD" # A-Z only, uppercase
        
        
def test_known_vector():
    assert encrypt("HELLO", 3) == "KHOOR"
    assert decrypt("KHOOR", 3) == "HELLO"
