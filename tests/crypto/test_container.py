"""KSK1 container tests. These run against AES and DES even before RC4 lands."""
from io import BytesIO

import pytest
import app.crypto
from app.crypto.base import REGISTRY, IntegrityError
from app.crypto.container import CHUNK_SIZE, decrypt_bytes, encrypt_bytes, encrypt_stream, decrypt_stream

DEK = b"k" * 32
CONTEXT = b"kosanku|1|3|ktp"


@pytest.mark.parametrize("size", [0, 1, CHUNK_SIZE - 1, CHUNK_SIZE, CHUNK_SIZE + 1])
def test_roundtrip(size):
    data = b"x" * size
    for suite in REGISTRY.values():
        blob = encrypt_bytes(suite, DEK, CONTEXT, data)
        assert decrypt_bytes(DEK, CONTEXT, blob) == data


def test_all_ciphers_single_source():
    suites = list(REGISTRY.values())
    outs = [BytesIO() for _ in suites]
    source = BytesIO(b"test" * (CHUNK_SIZE // 4 + 1))
    stats = encrypt_stream(suites, DEK, CONTEXT, source, outs)
    assert len(stats) == len(suites)
    assert all(decrypt_bytes(DEK, CONTEXT, dst.getvalue()) == b"test" * (CHUNK_SIZE // 4 + 1)
               for dst in outs)


@pytest.mark.parametrize("mode", ["header", "params", "record", "tag", "truncate", "append", "length"])
def test_tampering_rejected(mode):
    for suite in REGISTRY.values():
        blob = bytearray(encrypt_bytes(suite, DEK, CONTEXT, b"hello"))
        params_len = int.from_bytes(blob[10:12], "big")
        record_start = 12 + params_len
        if mode == "header":
            blob[4] ^= 1
        elif mode == "params":
            blob[12] ^= 1
        elif mode == "record":
            blob[record_start + 4] ^= 1
        elif mode == "tag":
            blob[-1] ^= 1
        elif mode == "truncate":
            del blob[-1:]
        elif mode == "append":
            blob += b"\x00\x00\x00\x01\x00"
        elif mode == "length":
            blob[record_start:record_start + 4] = b"\xff" * 4
        with pytest.raises(IntegrityError):
            decrypt_bytes(DEK, CONTEXT, bytes(blob))


def test_wrong_context_and_key():
    for suite in REGISTRY.values():
        blob = encrypt_bytes(suite, DEK, CONTEXT, b"hello")
        with pytest.raises(IntegrityError):
            decrypt_bytes(DEK, b"kosanku|2|3|ktp", blob)
        with pytest.raises(IntegrityError):
            decrypt_bytes(b"z" * 32, CONTEXT, blob)


def test_removed_last_record_rejected():
    for suite in REGISTRY.values():
        blob = encrypt_bytes(suite, DEK, CONTEXT, b"x" * (CHUNK_SIZE + 1))
        params_len = int.from_bytes(blob[10:12], "big")
        first = 12 + params_len
        first_len = int.from_bytes(blob[first:first + 4], "big")
        with pytest.raises(IntegrityError):
            decrypt_bytes(DEK, CONTEXT, blob[:first + 4 + first_len])


def test_short_reads():
    class ShortReader(BytesIO):
        def read(self, n=-1):
            return super().read(min(n, 13) if n > 0 else n)
    suite = next(iter(REGISTRY.values()))
    out = BytesIO()
    encrypt_stream([suite], DEK, CONTEXT, ShortReader(b"a" * (CHUNK_SIZE + 5)), [out])
    assert b"".join(decrypt_stream(DEK, CONTEXT, ShortReader(out.getvalue()))) == b"a" * (CHUNK_SIZE + 5)
