"""Key derivation helpers. Every suite derives its subkeys through these, so they all do it the same way."""

import hashlib
import hmac

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF


def hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes, length: int) -> bytes:
    return HKDF(ikm, length, salt, SHA256, context=info)


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()
