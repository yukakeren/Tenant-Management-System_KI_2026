"""Ata. Known-answer tests for raw AES-GCM, then tests for our aes_gcm.py suite."""

import pytest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.crypto import IntegrityError, get_suite
from app.crypto.aes_gcm import INFO, AesGcm, _Sealer
from app.crypto.kdf import hkdf_sha256

# GCM spec (McGrew & Viega) test case 16: 256-bit key, 96-bit IV, with AAD.
# Same vector set NIST CAVP uses; checks our call order (update(aad) → encrypt_and_digest).
K = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
IV = bytes.fromhex("cafebabefacedbaddecaf888")
P = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
C = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
)
T = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")


def test_gcm_known_answer_encrypt():
    c = AES.new(K, AES.MODE_GCM, nonce=IV, mac_len=16)
    c.update(A)
    ct, tag = c.encrypt_and_digest(P)
    assert (ct, tag) == (C, T)


def test_gcm_known_answer_decrypt():
    c = AES.new(K, AES.MODE_GCM, nonce=IV, mac_len=16)
    c.update(A)
    assert c.decrypt_and_verify(C, T) == P


# --- our suite ---

PREFIX = bytes.fromhex("0102030405060708")
AD = b"some associated data"


@pytest.fixture
def suite():
    return get_suite("aes")


@pytest.fixture
def dek():
    return get_random_bytes(32)


def test_registered_by_name_and_id():
    assert isinstance(get_suite("aes"), AesGcm)
    assert get_suite(1) is get_suite("aes")


def test_nonce_is_prefix_plus_index():
    s = _Sealer(bytes(32), PREFIX)
    assert s._nonce(0) == PREFIX + b"\x00\x00\x00\x00"
    assert s._nonce(1) == PREFIX + b"\x00\x00\x00\x01"
    assert s._nonce(2**32 - 1) == PREFIX + b"\xff\xff\xff\xff"
    assert len(s._nonce(0)) == 12  # 96-bit, the size GCM is designed for


@pytest.mark.parametrize("index", [-1, 2**32])
def test_nonce_out_of_range_raises(index):
    with pytest.raises(OverflowError):
        _Sealer(bytes(32), PREFIX)._nonce(index)


def test_opener_out_of_range_index_is_integrity_error(suite, dek):
    record = suite.sealer(dek, PREFIX).seal(0, b"hi", AD)
    with pytest.raises(IntegrityError):
        suite.opener(dek, PREFIX).open(2**32, record, AD)


def test_matches_raw_gcm_with_derived_key(suite, dek):
    # end-to-end wiring check: our record == AES-GCM(HKDF(dek), prefix||index, ad) done by hand
    key = hkdf_sha256(dek, salt=b"", info=INFO, length=32)
    c = AES.new(key, AES.MODE_GCM, nonce=PREFIX + (5).to_bytes(4, "big"), mac_len=16)
    c.update(AD)
    ct, tag = c.encrypt_and_digest(b"hello kosanku")
    assert suite.sealer(dek, PREFIX).seal(5, b"hello kosanku", AD) == ct + tag


def test_key_is_derived_not_the_dek_itself(suite, dek):
    key = hkdf_sha256(dek, salt=b"", info=INFO, length=32)
    assert key != dek
    c = AES.new(dek, AES.MODE_GCM, nonce=PREFIX + bytes(4), mac_len=16)
    c.update(AD)
    ct, tag = c.encrypt_and_digest(b"x" * 32)
    assert suite.sealer(dek, PREFIX).seal(0, b"x" * 32, AD) != ct + tag


def test_record_is_ciphertext_plus_16_byte_tag(suite, dek):
    for size in (0, 1, 100, 4096):
        assert len(suite.sealer(dek, PREFIX).seal(0, bytes(size), AD)) == size + 16


def test_same_params_same_output_different_params_different_output(suite, dek):
    # GCM itself is deterministic: the nonce is the only thing that changes the output.
    # That's why every file MUST get fresh params from new_params().
    data = b"3201234567890001"
    a = suite.sealer(dek, PREFIX).seal(0, data, AD)
    b = suite.sealer(dek, PREFIX).seal(0, data, AD)
    c = suite.sealer(dek, suite.new_params()).seal(0, data, AD)
    assert a == b
    assert a != c


def test_new_params_is_8_random_bytes(suite):
    params = {suite.new_params() for _ in range(100)}
    assert len(params) == 100
    assert all(len(p) == 8 for p in params)


@pytest.mark.parametrize("bad", [b"", bytes(7), bytes(9), bytes(12)])
def test_wrong_params_length(suite, dek, bad):
    with pytest.raises(ValueError):
        suite.sealer(dek, bad)
    with pytest.raises(IntegrityError):  # on read it means a broken header, not a bug
        suite.opener(dek, bad)


def test_tag_one_byte_short(suite, dek):
    record = suite.sealer(dek, PREFIX).seal(0, b"hello", AD)
    with pytest.raises(IntegrityError):
        suite.opener(dek, PREFIX).open(0, record[:-1], AD)


def test_empty_plaintext_still_authenticated(suite, dek):
    record = suite.sealer(dek, PREFIX).seal(0, b"", AD)
    assert suite.opener(dek, PREFIX).open(0, record, AD) == b""
    with pytest.raises(IntegrityError):
        suite.opener(dek, PREFIX).open(0, record, AD + b"!")
