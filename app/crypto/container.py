"""Authenticated, bounded-memory KSK1 file containers.

Format and associated data: docs/implementation/crypto-spec.md.
Every suite gets one sealer per file and receives chunks in ascending order.
"""
from __future__ import annotations

from dataclasses import dataclass
from time import perf_counter
from typing import BinaryIO, Iterator, Sequence

from .base import CipherSuite, IntegrityError, get_suite

MAGIC = b"KSK1"
VERSION = 1
CHUNK_SIZE = 1 << 20
MAX_RECORD_OVERHEAD = 64
HEADER_LEN = 12


@dataclass(frozen=True)
class EncStats:
    cipher: str
    ct_size: int
    enc_ms: float
    plain_size: int


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    """Fill a buffer even when a stream returns short reads."""
    out = bytearray()
    while len(out) < size:
        part = stream.read(size - len(out))
        if not part:
            break
        out.extend(part)
    return bytes(out)


def _header(cipher_id: int, chunk_size: int, params: bytes) -> bytes:
    if not (0 < chunk_size <= CHUNK_SIZE and 0 <= len(params) <= 65535):
        raise ValueError("invalid container parameters")
    return (MAGIC + bytes([VERSION, cipher_id]) + chunk_size.to_bytes(4, "big")
            + len(params).to_bytes(2, "big") + params)


def _chunk_ad(header: bytes, context: bytes, index: int, final: bool) -> bytes:
    if not 0 <= index < 2**32:
        raise IntegrityError()
    return header + context + index.to_bytes(8, "big") + bytes([final])


def _parse_header(src: BinaryIO) -> tuple[bytes, CipherSuite, bytes, int]:
    fixed = _read_exact(src, HEADER_LEN)
    if len(fixed) != HEADER_LEN or fixed[:4] != MAGIC or fixed[4] != VERSION:
        raise IntegrityError()
    try:
        suite = get_suite(fixed[5])
    except KeyError:
        raise IntegrityError() from None
    chunk_size = int.from_bytes(fixed[6:10], "big")
    params_len = int.from_bytes(fixed[10:12], "big")
    if not 0 < chunk_size <= CHUNK_SIZE or params_len > 64:
        raise IntegrityError()
    params = _read_exact(src, params_len)
    if len(params) != params_len:
        raise IntegrityError()
    return fixed + params, suite, params, chunk_size


def _record(src: BinaryIO, chunk_size: int) -> bytes | None:
    size_raw = _read_exact(src, 4)
    if not size_raw:
        return None
    if len(size_raw) != 4:
        raise IntegrityError()
    size = int.from_bytes(size_raw, "big")
    if not 0 < size <= chunk_size + MAX_RECORD_OVERHEAD:
        raise IntegrityError()
    rec = _read_exact(src, size)
    if len(rec) != size:
        raise IntegrityError()
    return rec


def encrypt_stream(
    suites: Sequence[CipherSuite], dek: bytes, context: bytes,
    src: BinaryIO, dsts: Sequence[BinaryIO],
) -> list[EncStats]:
    """Read plaintext once; write independently authenticated cipher containers."""
    if not suites or len(suites) != len(dsts):
        raise ValueError("one destination is required per cipher")
    headers, sealers, sizes, elapsed = [], [], [], []
    for suite, dst in zip(suites, dsts):
        params = suite.new_params()
        header = _header(suite.id, CHUNK_SIZE, params)
        dst.write(header)
        headers.append(header)
        sealers.append(suite.sealer(dek, params))
        sizes.append(len(header))
        elapsed.append(0.0)

    index, plain_size = 0, 0
    current = _read_exact(src, CHUNK_SIZE)
    while True:
        following = _read_exact(src, CHUNK_SIZE)
        final = not following
        plain_size += len(current)
        for j, (header, sealer, dst) in enumerate(zip(headers, sealers, dsts)):
            start = perf_counter()
            record = sealer.seal(index, current, _chunk_ad(header, context, index, final))
            elapsed[j] += perf_counter() - start
            if len(record) > CHUNK_SIZE + MAX_RECORD_OVERHEAD:
                raise ValueError("cipher record exceeds container limit")
            dst.write(len(record).to_bytes(4, "big"))
            dst.write(record)
            sizes[j] += 4 + len(record)
        if final:
            break
        index += 1
        current = following
    return [EncStats(s.name, sizes[i], elapsed[i] * 1000, plain_size)
            for i, s in enumerate(suites)]


def decrypt_stream(dek: bytes, context: bytes, src: BinaryIO) -> Iterator[bytes]:
    """Yield only authenticated chunks; callers must verify_stream first before HTTP streaming."""
    header, suite, params, chunk_size = _parse_header(src)
    try:
        opener = suite.opener(dek, params)
    except (ValueError, OverflowError, TypeError):
        raise IntegrityError() from None
    current = _record(src, chunk_size)
    if current is None:
        raise IntegrityError()
    index = 0
    while True:
        following = _record(src, chunk_size)
        final = following is None
        try:
            plaintext = opener.open(index, current, _chunk_ad(header, context, index, final))
        except (ValueError, OverflowError, TypeError, KeyError):
            raise IntegrityError() from None
        if len(plaintext) > chunk_size or (not final and len(plaintext) != chunk_size):
            raise IntegrityError()
        yield plaintext
        if final:
            return
        index += 1
        current = following


def verify_stream(dek: bytes, context: bytes, src: BinaryIO) -> None:
    for _ in decrypt_stream(dek, context, src):
        pass


def encrypt_bytes(suite: CipherSuite, dek: bytes, context: bytes, data: bytes) -> bytes:
    from io import BytesIO
    src, dst = BytesIO(data), BytesIO()
    encrypt_stream([suite], dek, context, src, [dst])
    return dst.getvalue()


def decrypt_bytes(dek: bytes, context: bytes, blob: bytes) -> bytes:
    from io import BytesIO
    return b"".join(decrypt_stream(dek, context, BytesIO(blob)))
