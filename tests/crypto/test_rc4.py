"""Person 3. Known-answer test first (day 1), suite tests once rc4.py exists (day 2)."""

from Crypto.Cipher import ARC4

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


# TODO day 2: per-file key = HMAC(dek, nonce), out-of-order index → IntegrityError.
