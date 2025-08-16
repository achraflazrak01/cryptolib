from cryptolib.exceptions import ValidationError

ALPH_NO_J = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

def _normalize_key(key: str) -> str:
    s = "".join(ch for ch in key.upper() if "A" <= ch <= "Z").replace("J", "I")
    if not s:
        raise ValidationError("Playfair key must contain at least one A-Z letter")
    return s

def build_square(key: str) -> str:
    """Return 25-char Playfair square string (row-major), with I/J merged."""
    s = _normalize_key(key)
    seen = set()
    order = []
    for ch in s:
        if ch not in seen:
            seen.add(ch)
            order.append(ch)
    for ch in ALPH_NO_J:
        if ch not in seen:
            seen.add(ch)
            order.append(ch)
    square = "".join(order)
    assert len(square) == 25
    return square

def at(square: str, r: int, c: int) -> int:
    """Char at (r, c) with wrap-around"""
    return square[(r % 5) * 5 + (c % 5)]

def loc_map(square: str) -> dict[str, tuple[int, int]]:
    """Map each letter in a 25-char row-major Playfair square to its (row, col) coords (0..4)."""
    return {square[i]: (i // 5, i % 5) for i in range(25)}

def prepare_pairs(text: str) -> list[tuple[str, str]]:
    """
    A-Z only, J -> I. Split into digraphs; if a pair has same letters, insert 'X';
    if last is single, pad with 'X'.
    """
    s = "".join(ch for ch in text.upper() if "A" <= ch <= "Z").replace("J", "I")
    pairs: list[tuple[str, str]] = []
    i = 0
    while i < len(s):
        a = s[i]
        if i + 1 == len(s):            # last single -> pad X
            pairs.append((a, "X"))
            i += 1
            continue
        b = s[i + 1]
        if a == b:                     # double letter -> insert X
            pairs.append((a, "X"))
            i += 1
        else:
            pairs.append((a, b))
            i += 2
    return pairs
