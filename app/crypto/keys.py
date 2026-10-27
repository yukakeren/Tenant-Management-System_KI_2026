"""Per-tenant DEK wrapping and authorization, using the server master key."""
from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from app.config import settings
from app.models import Role, User
from app.services.access import can_view_subject
from .base import IntegrityError


def load_master_key() -> bytes:
    key = settings.master_key
    if len(key) != 32:
        raise RuntimeError("MASTER_KEY must be 32 bytes")
    return key


def _aad(subject: User) -> bytes:
    if subject.id is None:
        raise ValueError("user must have a database id")
    return b"dek|" + str(subject.id).encode("ascii")


def create_dek(user: User) -> None:
    """Create a key for a tenant after db.flush(); caller commits the transaction."""
    if user.role != Role.tenant or user.wrapped_dek is not None:
        raise ValueError("DEK can only be created once for a tenant")
    nonce = get_random_bytes(12)
    cipher = AES.new(load_master_key(), AES.MODE_GCM, nonce=nonce)
    cipher.update(_aad(user))
    ct, tag = cipher.encrypt_and_digest(get_random_bytes(32))
    user.wrapped_dek = nonce + ct + tag


def unwrap_dek(subject: User, actor: User) -> bytes:
    """Authorize before decrypting. Admin is never allowed to unwrap a DEK."""
    if (subject.role != Role.tenant or actor.role == Role.admin
            or not can_view_subject(actor, subject)
            or not subject.wrapped_dek):
        raise PermissionError("not authorized")
    blob = subject.wrapped_dek
    if len(blob) != 60:
        raise IntegrityError()
    cipher = AES.new(load_master_key(), AES.MODE_GCM, nonce=blob[:12])
    cipher.update(_aad(subject))
    try:
        return cipher.decrypt_and_verify(blob[12:-16], blob[-16:])
    except ValueError:
        raise IntegrityError() from None


def destroy_dek(subject: User) -> None:
    """Remove the wrapped key from the active database (not from external backups)."""
    subject.wrapped_dek = None
