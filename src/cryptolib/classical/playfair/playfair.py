from .helpers import at, build_square, prepare_pairs, loc_map

def encrypt(plaintext: str, key: str) -> str:
    """Playfair encrypt. Builds 5×5 square from key (I/J merged), splits plaintext into digraphs (inserting/padding 'X'), then applies rules: same row→right, same column→down, rectangle→swap columns. Returns A–Z uppercase ciphertext."""
    sq = build_square(key)
    loc = loc_map(sq)
    out = []
    for a, b in prepare_pairs(plaintext):
        ra, ca = loc[a]
        rb, cb = loc[b]
        if ra == rb:         # same row -> shift right
            out.append(at(sq, ra, ca + 1))
            out.append(at(sq, rb, cb + 1))
        elif ca == cb:       # same column -> shift down
            out.append(at(sq, ra + 1, ca))
            out.append(at(sq, rb + 1, cb))
        else:                # rectangle -> swap columns
            out.append(at(sq, ra, cb))
            out.append(at(sq, rb, ca))
    return "".join(out)

def decrypt(ciphertext: str, key: str) -> str:
    """Playfair decrypt. Builds 5×5 square from key (I/J merged), cleans ciphertext to A–Z (J→I) and pads final single with 'X', then applies inverse rules: same row→left, same column→up, rectangle→swap columns. Returns A–Z uppercase plaintext (fillers not removed)."""
    sq = build_square(key)
    loc = loc_map(sq)
    s = "".join(ch for ch in ciphertext.upper() if "A" <= ch <= "Z").replace("J", "I")
    if len(s) % 2 == 1:
        s += "X"
    out = []
    i = 0
    while i < len(s):
        a, b = s[i], s[i + 1]
        ra, ca = loc[a]
        rb, cb = loc[b]
        if ra == rb:         # same row -> shift left
            out.append(at(sq, ra, ca - 1))
            out.append(at(sq, rb, cb - 1))
        elif ca == cb:       # same column -> shift up
            out.append(at(sq, ra - 1, ca))
            out.append(at(sq, rb - 1, cb))
        else:                # rectangle -> swap columns
            out.append(at(sq, ra, cb))
            out.append(at(sq, rb, ca))
        i += 2
    return "".join(out)
