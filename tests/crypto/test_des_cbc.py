"""Person 2. Known-answer test first (day 1), suite tests once des_cbc.py exists (day 2)."""

from Crypto.Cipher import DES

# Classic textbook DES vector (used in most DES walkthroughs).
KEY = bytes.fromhex("133457799BBCDFF1")
PT = bytes.fromhex("0123456789ABCDEF")
CT = bytes.fromhex("85E813540F0AB405")


def test_des_known_answer_ecb():
    assert DES.new(KEY, DES.MODE_ECB).encrypt(PT) == CT


def test_des_cbc_zero_iv_first_block_matches_ecb():
    assert DES.new(KEY, DES.MODE_CBC, iv=bytes(8)).encrypt(PT) == CT


def test_parity_bits_are_ignored():
    # flipping the low bit of every key byte gives the same cipher → 56-bit effective key
    flipped = bytes(b ^ 0x01 for b in KEY)
    assert DES.new(flipped, DES.MODE_ECB).encrypt(PT) == CT


# TODO day 2: _odd_parity, IV flip → IntegrityError, ct length not multiple of 8 → IntegrityError.
