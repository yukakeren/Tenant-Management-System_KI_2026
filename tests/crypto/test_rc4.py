"""Ajil. Known-answer test first (day 1), suite tests once rc4.py exists (day 2)."""

import os
import pytest
from Crypto.Cipher import ARC4
from app.crypto.rc4 import RC4Drop3072Cipher, derive_rc4_key, IntegrityError

# RFC 6229, 40-bit key 0x0102030405, keystream at offsets 0 and 16
RFC_KEY = bytes.fromhex("0102030405")
RFC_OFF_0 = bytes.fromhex("b2396305f03dc027ccc3524a0a1118a8")
RFC_OFF_16 = bytes.fromhex("6982944f18fc82d589c403a47a0d0919")


def keystream(key: bytes, n: int, drop: int = 0) -> bytes:
    return ARC4.new(key, drop=drop).encrypt(bytes(n))


def test_rc4_wikipedia_vector():
    assert ARC4.new(b"Key").encrypt(b"Plaintext") == bytes.fromhex("BBF316E8D940AF0AD3")


def test_rc4_rfc6229_offset_0_and_16():
    ks = keystream(RFC_KEY, 32)
    assert ks[:16] == RFC_OFF_0
    assert ks[16:32] == RFC_OFF_16


def test_drop_3072_really_skips():
    full = keystream(RFC_KEY, 3072 + 16)
    assert keystream(RFC_KEY, 16, drop=3072) == full[3072:]


def test_rc4_is_malleable_without_mac():
    # why rc4.py MUST add an HMAC: flipping ciphertext bit k flips plaintext bit k, undetected
    pt = b"NIK=3201234567890001"
    ct = bytearray(ARC4.new(RFC_KEY).encrypt(pt))
    ct[4] ^= ord("3") ^ ord("9")
    assert ARC4.new(RFC_KEY).decrypt(bytes(ct)) == b"NIK=9201234567890001"


def test_rc4_per_file_key_unique_per_nonce():
    dek = os.urandom(32)
    nonce1 = os.urandom(16)
    nonce2 = os.urandom(16)
    
    k1 = derive_rc4_key(dek, nonce1)
    k2 = derive_rc4_key(dek, nonce2)
    
    assert len(k1) == 32
    assert len(k2) == 32
    assert k1 != k2, "Key per-file harus unik untuk setiap nonce"


def test_rc4_roundtrip():
    dek = os.urandom(32)
    plaintext = b"Berkas KTP Tenant Rahasia 3201234567890001"
    
    nonce, ciphertext, tag = RC4Drop3072Cipher.encrypt(plaintext, dek)
    assert ciphertext != plaintext
    
    decrypted = RC4Drop3072Cipher.decrypt(nonce, ciphertext, tag, dek)
    assert decrypted == plaintext


def test_rc4_mac_prevents_malleability():
    """Memastikan bit-flipping yang sebelumnya lolos, sekarang DITOLAK oleh HMAC."""
    dek = os.urandom(32)
    pt = b"NIK=3201234567890001"
    
    nonce, ciphertext, tag = RC4Drop3072Cipher.encrypt(pt, dek)
    
    # Tamper 1 byte pada ciphertext
    tampered_ct = bytearray(ciphertext)
    tampered_ct[4] ^= ord("3") ^ ord("9")
    
    # Harus melempar IntegrityError, bukan terdekripsi jadi data palsu
    with pytest.raises(IntegrityError):
        RC4Drop3072Cipher.decrypt(nonce, bytes(tampered_ct), tag, dek)


def test_rc4_tampered_nonce_fails():
    dek = os.urandom(32)
    pt = b"Data Penting"
    nonce, ciphertext, tag = RC4Drop3072Cipher.encrypt(pt, dek)
    
    tampered_nonce = bytearray(nonce)
    tampered_nonce[0] ^= 0xFF
    
    with pytest.raises(IntegrityError):
        RC4Drop3072Cipher.decrypt(bytes(tampered_nonce), ciphertext, tag, dek)