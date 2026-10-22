"""Fake suite so the contract tests and the container can be built before the real ciphers exist.
NOT secure. Never register it in the app."""

import hashlib
import hmac

from Crypto.Random import get_random_bytes

from app.crypto.base import CipherSuite, IntegrityError
from app.crypto.kdf import hkdf_sha256, hmac_sha256


def _keystream(key: bytes, index: int, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + index.to_bytes(8, "big") + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


class _XorChunks:
    def __init__(self, dek: bytes, params: bytes):
        self.key = hkdf_sha256(dek, salt=params, info=b"test/xor", length=32)

    def seal(self, index, plaintext, ad):
        ct = bytes(a ^ b for a, b in zip(plaintext, _keystream(self.key, index, len(plaintext))))
        return ct + hmac_sha256(self.key, ad + ct)

    def open(self, index, record, ad):
        if len(record) < 32:
            raise IntegrityError()
        ct, tag = record[:-32], record[-32:]
        if not hmac.compare_digest(tag, hmac_sha256(self.key, ad + ct)):
            raise IntegrityError()
        return bytes(a ^ b for a, b in zip(ct, _keystream(self.key, index, len(ct))))


class XorSuite(CipherSuite):
    id, name = 99, "xor-test"

    def new_params(self):
        return get_random_bytes(16)

    def sealer(self, dek, params):
        return _XorChunks(dek, params)

    def opener(self, dek, params):
        return _XorChunks(dek, params)
