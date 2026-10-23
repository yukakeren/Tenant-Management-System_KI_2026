"""Ata. Known-answer test first (day 1), suite tests once aes_gcm.py exists (day 2)."""

from Crypto.Cipher import AES

# GCM spec (McGrew & Viega) test case 16: 256-bit key, 96-bit IV, with AAD.
# Same vector set NIST CAVP uses; checks our call order (update(aad) → encrypt_and_digest).
K = bytes.fromhex("feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308")
IV = bytes.fromhex("cafebabefacedbaddecaf888")
P = bytes.fromhex(
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
A = bytes.fromhex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
C = bytes.fromhex(
    "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
    "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
)
T = bytes.fromhex("76fc6ece0f4e1768cddf8853bb2d551b")


def test_gcm_known_answer_encrypt():
    c = AES.new(K, AES.MODE_GCM, nonce=IV, mac_len=16)
    c.update(A)
    ct, tag = c.encrypt_and_digest(P)
    assert (ct, tag) == (C, T)


def test_gcm_known_answer_decrypt():
    c = AES.new(K, AES.MODE_GCM, nonce=IV, mac_len=16)
    c.update(A)
    assert c.decrypt_and_verify(C, T) == P


# TODO day 2: nonce derivation (prefix || u32 index), index 2**32 raises, params length check.
