"""Every registered suite must pass this file. Written against base.py only.

Chunk-level for now. Container-level cases (truncate / append / drop last record, header flips)
go into test_container.py on day 2, once container.py exists.
"""

import random

import pytest
from Crypto.Random import get_random_bytes

import app.crypto  # noqa: F401  (registers the real suites)
from app.crypto.base import REGISTRY, IntegrityError

from ._xor_suite import XorSuite

SUITES = [XorSuite(), *REGISTRY.values()]
CHUNK = 1 << 20
SIZES = [0, 1, 7, 8, 9, 4096, CHUNK - 1, CHUNK]
CONTEXT = b"kosanku|1|1|ktp"


def ad_for(index: int, final: bool, context: bytes = CONTEXT) -> bytes:
    # same shape as container.py will build: file_ad || u64(index) || u8(final)
    return b"HEADER" + context + index.to_bytes(8, "big") + bytes([final])


def seal_all(suite, dek, params, chunks, context=CONTEXT):
    s = suite.sealer(dek, params)
    return [s.seal(i, c, ad_for(i, i == len(chunks) - 1, context)) for i, c in enumerate(chunks)]


def open_all(suite, dek, params, records, context=CONTEXT):
    o = suite.opener(dek, params)
    return [o.open(i, r, ad_for(i, i == len(records) - 1, context)) for i, r in enumerate(records)]


@pytest.fixture
def dek():
    return get_random_bytes(32)


pytestmark = pytest.mark.parametrize("suite", SUITES, ids=lambda s: s.name)


@pytest.mark.parametrize("size", SIZES)
def test_roundtrip_single_chunk(suite, dek, size):
    params = suite.new_params()
    data = get_random_bytes(size)
    assert open_all(suite, dek, params, seal_all(suite, dek, params, [data])) == [data]


def test_roundtrip_many_chunks(suite, dek):
    params = suite.new_params()
    chunks = [get_random_bytes(CHUNK), get_random_bytes(CHUNK), get_random_bytes(5)]
    assert open_all(suite, dek, params, seal_all(suite, dek, params, chunks)) == chunks


def test_ciphertext_is_not_plaintext(suite, dek):
    params = suite.new_params()
    data = b"3201234567890001" * 64  # NIK-looking, repetitive
    (record,) = seal_all(suite, dek, params, [data])
    assert data[:16] not in record


def test_fresh_params_each_file(suite, dek):
    assert suite.new_params() != suite.new_params()
    data = bytes(1000)
    a = seal_all(suite, dek, suite.new_params(), [data])
    b = seal_all(suite, dek, suite.new_params(), [data])
    assert a != b


@pytest.mark.parametrize("where", ["first", "middle", "last"])
def test_flip_byte_in_record(suite, dek, where):
    params = suite.new_params()
    (record,) = seal_all(suite, dek, params, [get_random_bytes(100)])
    pos = {"first": 0, "middle": len(record) // 2, "last": len(record) - 1}[where]
    bad = bytearray(record)
    bad[pos] ^= 0x01
    with pytest.raises(IntegrityError):
        open_all(suite, dek, params, [bytes(bad)])


def test_wrong_dek(suite, dek):
    params = suite.new_params()
    records = seal_all(suite, dek, params, [b"hello"])
    with pytest.raises(IntegrityError):
        open_all(suite, get_random_bytes(32), params, records)


def test_wrong_params(suite, dek):
    params = suite.new_params()
    records = seal_all(suite, dek, params, [b"hello"])
    with pytest.raises(IntegrityError):
        open_all(suite, dek, suite.new_params(), records)


def test_wrong_context(suite, dek):
    params = suite.new_params()
    records = seal_all(suite, dek, params, [b"hello"], context=b"kosanku|1|1|ktp")
    with pytest.raises(IntegrityError):
        open_all(suite, dek, params, records, context=b"kosanku|2|1|ktp")


def test_swap_chunks(suite, dek):
    params = suite.new_params()
    a, b, c = seal_all(suite, dek, params, [b"A" * 64, b"B" * 64, b"C" * 64])
    with pytest.raises(IntegrityError):
        open_all(suite, dek, params, [b, a, c])


def test_final_flag_is_authenticated(suite, dek):
    # sealed as NOT final, opened as final → must fail (this is what stops truncation later)
    params = suite.new_params()
    record = suite.sealer(dek, params).seal(0, b"x" * 32, ad_for(0, final=False))
    with pytest.raises(IntegrityError):
        suite.opener(dek, params).open(0, record, ad_for(0, final=True))


@pytest.mark.parametrize("record", [b"", b"\x00", b"\x00" * 15])
def test_short_record(suite, dek, record):
    with pytest.raises(IntegrityError):
        suite.opener(dek, suite.new_params()).open(0, record, ad_for(0, True))


def test_only_integrity_error_escapes(suite, dek):
    rng = random.Random(1234)
    params = suite.new_params()
    (record,) = seal_all(suite, dek, params, [get_random_bytes(300)])
    for _ in range(200):
        bad = bytearray(record)
        mode = rng.choice(["flip", "cut", "extend"])
        if mode == "flip":
            bad[rng.randrange(len(bad))] ^= 1 << rng.randrange(8)
        elif mode == "cut":
            del bad[rng.randrange(len(bad)):]
        else:
            bad += bytes([rng.randrange(256)]) * rng.randint(1, 9)
        with pytest.raises(IntegrityError):  # a ValueError/KeyError here is a bug in the suite
            open_all(suite, dek, params, [bytes(bad)])
