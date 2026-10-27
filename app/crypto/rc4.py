"""
RC4-drop3072 with HMAC-SHA256 Encrypt-then-MAC.
"""

import hmac
import hashlib
import os
from Crypto.Cipher import ARC4

try:
    from app.crypto.base import IntegrityError
except ImportError:
    class IntegrityError(Exception):
        pass


def derive_rc4_key(dek: bytes, nonce: bytes) -> bytes:
    return hmac.new(dek, nonce, hashlib.sha256).digest()


class RC4Drop3072Cipher:
    NONCE_SIZE = 16
    TAG_SIZE = 32

    @classmethod
    def encrypt(cls, plaintext: bytes, dek: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes, bytes]:

        if nonce is None:
            nonce = os.urandom(cls.NONCE_SIZE)

        file_key = derive_rc4_key(dek, nonce)
        
        cipher = ARC4.new(file_key, drop=3072)
        ciphertext = cipher.encrypt(plaintext)

        mac_data = nonce + ciphertext
        tag = hmac.new(dek, mac_data, hashlib.sha256).digest()

        return nonce, ciphertext, tag

    @classmethod
    def decrypt(cls, nonce: bytes, ciphertext: bytes, tag: bytes, dek: bytes) -> bytes:
        mac_data = nonce + ciphertext
        expected_tag = hmac.new(dek, mac_data, hashlib.sha256).digest()
        
        if not hmac.compare_digest(tag, expected_tag):
            try:
                raise IntegrityError()
            except TypeError:
                raise IntegrityError("RC4 ciphertext or nonce has been tampered with.")

        file_key = derive_rc4_key(dek, nonce)
        cipher = ARC4.new(file_key, drop=3072)
        return cipher.decrypt(ciphertext)


from app.crypto.base import CipherSuite, register
from app.crypto.kdf import hkdf_sha256


class _ChunkRC4:
    def __init__(self, dek: bytes, nonce: bytes):
        self.cipher = ARC4.new(derive_rc4_key(dek, nonce), drop=3072)
        self.mac_key = hkdf_sha256(dek, salt=nonce, info=b"kosanku/rc4/mac/v1", length=32)
        self.next_index = 0

    def _check_order(self, index: int):
        if index != self.next_index:
            raise IntegrityError()
        self.next_index += 1


class _Sealer(_ChunkRC4):
    def seal(self, index: int, plaintext: bytes, ad: bytes) -> bytes:
        self._check_order(index)
        ciphertext = self.cipher.encrypt(plaintext)
        tag = hmac.new(self.mac_key, ad + ciphertext, hashlib.sha256).digest()
        return ciphertext + tag


class _Opener(_ChunkRC4):
    def open(self, index: int, record: bytes, ad: bytes) -> bytes:
        if len(record) < 32:
            raise IntegrityError()
        ciphertext, tag = record[:-32], record[-32:]
        expected_tag = hmac.new(self.mac_key, ad + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expected_tag):
            raise IntegrityError()
        self._check_order(index)
        return self.cipher.decrypt(ciphertext)


@register
class Rc4(CipherSuite):
    id = 3
    name = "rc4"

    def new_params(self) -> bytes:
        return os.urandom(16)

    def sealer(self, dek: bytes, params: bytes) -> _Sealer:
        return _Sealer(dek, params)

    def opener(self, dek: bytes, params: bytes) -> _Opener:
        return _Opener(dek, params)
