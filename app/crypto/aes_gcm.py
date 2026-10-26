"""AES-256-GCM suite (Ata). See docs/implementation/crypto-spec.md, "AES-256-GCM".

params = 8 random bytes (nonce prefix), new for every file
key    = HKDF(dek, info="kosanku/aes-gcm/v1"), 32 bytes
nonce  = params || u32(index), so it never repeats inside a file
record = ciphertext || 16-byte tag (the tag also covers ad)
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .base import CipherSuite, IntegrityError, register
from .kdf import hkdf_sha256

INFO = b"kosanku/aes-gcm/v1"
PREFIX_LEN = 8
TAG_LEN = 16
MAX_CHUNKS = 2**32


def _derive_key(dek: bytes) -> bytes:
    return hkdf_sha256(dek, salt=b"", info=INFO, length=32)


class _Sealer:
    def __init__(self, key: bytes, prefix: bytes):
        self.key = key
        self.prefix = prefix

    def _nonce(self, index: int) -> bytes:
        if not 0 <= index < MAX_CHUNKS:
            raise OverflowError("too many chunks for one file")
        return self.prefix + index.to_bytes(4, "big")

    def _cipher(self, index: int, ad: bytes):
        c = AES.new(self.key, AES.MODE_GCM, nonce=self._nonce(index), mac_len=TAG_LEN)
        c.update(ad)
        return c

    def seal(self, index: int, plaintext: bytes, ad: bytes) -> bytes:
        ct, tag = self._cipher(index, ad).encrypt_and_digest(plaintext)
        return ct + tag


class _Opener(_Sealer):
    def open(self, index: int, record: bytes, ad: bytes) -> bytes:
        if len(record) < TAG_LEN:
            raise IntegrityError()
        try:
            c = self._cipher(index, ad)
        except OverflowError:
            raise IntegrityError() from None
        try:
            # decrypt_and_verify never hands back plaintext that failed the tag check
            return c.decrypt_and_verify(record[:-TAG_LEN], record[-TAG_LEN:])
        except ValueError:
            raise IntegrityError() from None


@register
class AesGcm(CipherSuite):
    id = 1
    name = "aes"

    def new_params(self) -> bytes:
        return get_random_bytes(PREFIX_LEN)

    def sealer(self, dek: bytes, params: bytes) -> _Sealer:
        if len(params) != PREFIX_LEN:
            raise ValueError(f"AES-GCM params must be {PREFIX_LEN} bytes")
        return _Sealer(_derive_key(dek), params)

    def opener(self, dek: bytes, params: bytes) -> _Opener:
        if len(params) != PREFIX_LEN:
            raise IntegrityError()  # the header is probably corrupted
        return _Opener(_derive_key(dek), params)
