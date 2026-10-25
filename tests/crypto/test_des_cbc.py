"""Melvan. Known-answer test first (day 1), suite tests for des_cbc.py (day 2)."""

import pytest
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes

from app.crypto import IntegrityError, get_suite
from app.crypto.des_cbc import DesCbc, _odd_parity

# Classic textbook DES vector (used in most DES walkthroughs).
KEY = bytes.fromhex("133457799BBCDFF1")
PT = bytes.fromhex("0123456789ABCDEF")
CT = bytes.fromhex("85E813540F0AB405")

AD = b"some associated data"


def test_des_known_answer_ecb():
    assert DES.new(KEY, DES.MODE_ECB).encrypt(PT) == CT


def test_des_cbc_zero_iv_first_block_matches_ecb():
    assert DES.new(KEY, DES.MODE_CBC, iv=bytes(8)).encrypt(PT) == CT


def test_parity_bits_are_ignored():
    # flipping the low bit of every key byte gives the same cipher → 56-bit effective key
    flipped = bytes(b ^ 0x01 for b in KEY)
    assert DES.new(flipped, DES.MODE_ECB).encrypt(PT) == CT


# --- our suite tests ---


@pytest.fixture
def suite():
    return get_suite("des")


@pytest.fixture
def dek():
    return get_random_bytes(32)


def test_registered_by_name_and_id():
    assert isinstance(get_suite("des"), DesCbc)
    assert get_suite(2) is get_suite("des")


def test_odd_parity_guarantees_odd_number_of_ones():
    # DES hardware parity expects an odd number of 1-bits in every byte
    raw_bytes = bytes(range(256))
    adjusted = _odd_parity(raw_bytes)
    assert len(adjusted) == len(raw_bytes)
    for b in adjusted:
        assert bin(b).count("1") % 2 == 1


def test_flip_bit_in_iv_raises_integrity_error(suite, dek):
    # Without the MAC, flipping bits in the IV would silently flip matching bits
    # in plaintext block 1. Encrypt-then-MAC ensures IV tampering raises IntegrityError.
    salt = suite.new_params()
    record = suite.sealer(dek, salt).seal(0, b"Secret boarding house tenant data", AD)
    bad_iv_record = bytearray(record)
    bad_iv_record[0] ^= 0x01  # flip a bit in IV
    with pytest.raises(IntegrityError):
        suite.opener(dek, salt).open(0, bytes(bad_iv_record), AD)


def test_ciphertext_length_not_multiple_of_eight_raises_integrity_error(suite, dek):
    # Any truncated or non-block-aligned record must raise IntegrityError, not ValueError
    salt = suite.new_params()
    record = suite.sealer(dek, salt).seal(0, b"A short text", AD)
    # Cut 1 byte off the ciphertext portion (record has 8B IV, n*8B CT, 32B tag)
    bad_record = record[:15] + record[16:]
    with pytest.raises(IntegrityError):
        suite.opener(dek, salt).open(0, bad_record, AD)


def test_same_plaintext_two_chunks_gives_different_ciphertext(suite, dek):
    # Because each seal() call generates a fresh, unpredictable random 8-byte IV,
    # encrypting identical plaintext yields completely different ciphertext records.
    salt = suite.new_params()
    sealer = suite.sealer(dek, salt)
    plain = b"Repeated room walkthrough video chunk payload"
    rec1 = sealer.seal(0, plain, AD)
    rec2 = sealer.seal(1, plain, AD)
    assert rec1 != rec2


def test_new_params_is_16_random_bytes(suite):
    salts = {suite.new_params() for _ in range(100)}
    assert len(salts) == 100
    assert all(len(s) == 16 for s in salts)


@pytest.mark.parametrize("bad", [b"", bytes(8), bytes(15), bytes(17)])
def test_wrong_params_length(suite, dek, bad):
    with pytest.raises(ValueError):
        suite.sealer(dek, bad)
    with pytest.raises(IntegrityError):
        suite.opener(dek, bad)
