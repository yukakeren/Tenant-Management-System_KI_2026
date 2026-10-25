"""DES-CBC + HMAC-SHA256 cipher suite (Melvan).

Cipher: DES in CBC mode with PKCS#7 padding.
Tag:    HMAC-SHA256 over (ad || iv || ciphertext) — Encrypt-then-MAC.
Params: 16 random bytes (salt), new for every file.

Subkeys:
  enc key = HKDF(dek, salt, "kosanku/des-cbc/enc/v1", 8 bytes), parity adjusted
  mac key = HKDF(dek, salt, "kosanku/des-cbc/mac/v1", 32 bytes)
"""

import hmac
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

from .base import CipherSuite, IntegrityError, register
from .kdf import hkdf_sha256, hmac_sha256

ENC_INFO = b"kosanku/des-cbc/enc/v1"
MAC_INFO = b"kosanku/des-cbc/mac/v1"
SALT_LEN = 16
IV_LEN = 8
TAG_LEN = 32


def _odd_parity(key: bytes) -> bytes:
    """DES ignores the last bit of every byte (used for parity in hardware).
    Setting odd parity makes the effective 56-bit key explicit.
    """
    return bytes((b & 0xFE) | (bin(b >> 1).count("1") + 1) % 2 for b in key)


def _keys(dek: bytes, salt: bytes) -> tuple[bytes, bytes]:
    enc = _odd_parity(hkdf_sha256(dek, salt=salt, info=ENC_INFO, length=8))
    mac = hkdf_sha256(dek, salt=salt, info=MAC_INFO, length=32)
    return enc, mac


class _Sealer:
    def __init__(self, dek: bytes, salt: bytes):
        self.enc, self.mac = _keys(dek, salt)

    def seal(self, index: int, plaintext: bytes, ad: bytes) -> bytes:
        iv = get_random_bytes(IV_LEN)
        ct = DES.new(self.enc, DES.MODE_CBC, iv=iv).encrypt(pad(plaintext, 8))
        tag = hmac_sha256(self.mac, ad + iv + ct)
        return iv + ct + tag


class _Opener(_Sealer):
    def open(self, index: int, record: bytes, ad: bytes) -> bytes:
        # Minimum record: IV (8) + at least 1 padded block (8) + TAG (32) = 48 bytes
        # Also, ciphertext length must be a multiple of 8
        if len(record) < IV_LEN + 8 + TAG_LEN or (len(record) - IV_LEN - TAG_LEN) % 8 != 0:
            raise IntegrityError()

        iv = record[:IV_LEN]
        ct = record[IV_LEN:-TAG_LEN]
        tag = record[-TAG_LEN:]

        # Encrypt-then-MAC: verify MAC in constant time before attempting decryption/unpadding
        expected_tag = hmac_sha256(self.mac, ad + iv + ct)
        if not hmac.compare_digest(tag, expected_tag):
            raise IntegrityError()

        try:
            pt = DES.new(self.enc, DES.MODE_CBC, iv=iv).decrypt(ct)
            return unpad(pt, 8)
        except ValueError:
            # Bad padding or corrupt block — never leak whether it was padding or MAC
            raise IntegrityError() from None


@register
class DesCbc(CipherSuite):
    id = 2
    name = "des"

    def new_params(self) -> bytes:
        return get_random_bytes(SALT_LEN)

    def sealer(self, dek: bytes, params: bytes) -> _Sealer:
        if len(params) != SALT_LEN:
            raise ValueError(f"DES-CBC params must be {SALT_LEN} bytes")
        return _Sealer(dek, params)

    def opener(self, dek: bytes, params: bytes) -> _Opener:
        if len(params) != SALT_LEN:
            raise IntegrityError()
        return _Opener(dek, params)
