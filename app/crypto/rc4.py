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