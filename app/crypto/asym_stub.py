"""Stub for asym.py — replace with Ata's real implementation at integration."""
import base64

def encrypt_key(public_pem: str, key: bytes) -> str:
    """Stub: returns base64 of key (NOT real RSA encryption)."""
    return base64.b64encode(b"STUB_ENC:" + key).decode()

def decrypt_key(private_pem: str, token: str) -> bytes:
    import base64
    raw = base64.b64decode(token)
    return raw[len(b"STUB_ENC:"):]
