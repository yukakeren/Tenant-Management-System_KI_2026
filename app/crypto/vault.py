"""Encrypted document storage. Routes should use this API, not raw cipher modules.

The vault commits its own DB transactions for store/shred. Callers should not
wrap those operations in a larger transaction without coordinating that policy.
"""
from __future__ import annotations

import os
import tempfile
from io import BytesIO
from pathlib import Path
from typing import BinaryIO, Iterator

from sqlalchemy import select
from sqlalchemy.orm import object_session

from app.config import settings
from app.models import CipherName, ItemKind, SecretBlob, SecretItem, User, Role, DeletionRequest, DeletionStatus
from app.services.access import can_view_subject
from .base import IntegrityError, get_suite
from .container import encrypt_stream, decrypt_stream, verify_stream
from .keys import unwrap_dek, destroy_dek

CIPHERS = ("aes", "des", "rc4")


def _session(subject: User):
    db = object_session(subject)
    if db is None:
        raise ValueError("subject must be attached to a database session")
    return db


def _kind(kind: ItemKind | str) -> ItemKind:
    return kind if isinstance(kind, ItemKind) else ItemKind(kind)


def _context(item: SecretItem) -> bytes:
    return f"kosanku|{item.subject_id}|{item.id}|{item.kind.value}".encode("ascii")


def _safe_path(path: str | Path) -> Path:
    root = settings.storage_dir.resolve()
    target = Path(path).resolve()
    if not target.is_relative_to(root):
        raise IntegrityError()
    return target


def _get_item(subject: User, kind: ItemKind | str) -> SecretItem | None:
    db = _session(subject)
    return db.scalar(select(SecretItem).where(
        SecretItem.subject_id == subject.id, SecretItem.kind == _kind(kind)))


def _get_blob(item: SecretItem, cipher: str) -> SecretBlob:
    db = _session_for_item(item)
    blob = db.scalar(select(SecretBlob).where(
        SecretBlob.item_id == item.id, SecretBlob.cipher == CipherName(cipher)))
    if blob is None:
        raise FileNotFoundError("encrypted document not found")
    return blob


def _session_for_item(item: SecretItem):
    db = object_session(item)
    if db is None:
        raise ValueError("item must be attached to a database session")
    return db


def _check_cipher(blob: SecretBlob, path: Path) -> None:
    """Reject a blob whose declared cipher doesn't match its KSK1 header."""
    with path.open("rb") as f:
        prefix = f.read(6)
    if len(prefix) != 6 or prefix[:4] != b"KSK1" or prefix[4] != 1:
        raise IntegrityError()
    if prefix[5] != get_suite(blob.cipher.value).id:
        raise IntegrityError()


def store_item(subject: User, kind: ItemKind | str, src: BinaryIO,
               mime: str, actor: User) -> SecretItem:
    """Encrypt once into three independent KSK1 files and update DB metadata.

    Temporary files are written completely before replacing existing copies.
    On an exception before commit, original files are restored.
    """
    if actor.role != Role.tenant or actor.id != subject.id:
        raise PermissionError("only the tenant may upload their own documents")
    dek = unwrap_dek(subject, actor)
    db = _session(subject)
    item = _get_item(subject, kind)
    is_new = item is None
    if item is None:
        item = SecretItem(subject_id=subject.id, kind=_kind(kind), mime=mime, plain_size=0)
        db.add(item)
        db.flush()  # item id is required for authenticated context
    root = settings.storage_dir.resolve()
    folder = root / str(subject.id)
    folder.mkdir(parents=True, exist_ok=True)
    names = {c: folder / f"{item.id}.{c}.bin" for c in CIPHERS}
    replaced: list[str] = []
    backed_up: list[str] = []
    with tempfile.TemporaryDirectory(prefix=".upload-", dir=folder) as temp:
        work = Path(temp)
        try:
            staged = {c: work / f"{c}.tmp" for c in CIPHERS}
            with (staged["aes"].open("wb") as aes,
                  staged["des"].open("wb") as des,
                  staged["rc4"].open("wb") as rc4):
                stats = encrypt_stream([get_suite(c) for c in CIPHERS], dek,
                                       _context(item), src, [aes, des, rc4])
                for f in (aes, des, rc4):
                    f.flush()
                    os.fsync(f.fileno())
            for c in CIPHERS:
                if names[c].exists():
                    os.replace(names[c], work / f"{c}.backup")
                    backed_up.append(c)
                os.replace(staged[c], names[c])
                replaced.append(c)
            for old in list(db.scalars(select(SecretBlob).where(SecretBlob.item_id == item.id))):
                db.delete(old)
            db.flush()
            item.mime = mime
            item.plain_size = stats[0].plain_size
            for st in stats:
                db.add(SecretBlob(item_id=item.id, cipher=CipherName(st.cipher),
                                  path=str(names[st.cipher]), ct_size=st.ct_size,
                                  enc_ms=st.enc_ms))
            db.commit()
        except Exception:
            db.rollback()
            for c in replaced:
                names[c].unlink(missing_ok=True)
            for c in backed_up:
                backup = work / f"{c}.backup"
                if backup.exists():
                    os.replace(backup, names[c])
            raise
    return item


def store_bytes(subject: User, kind: ItemKind | str, data: bytes,
                actor: User, mime: str = "application/json") -> SecretItem:
    return store_item(subject, kind, BytesIO(data), mime, actor)


def _read_target(subject: User, kind: ItemKind | str, cipher: str, actor: User):
    dek = unwrap_dek(subject, actor, _kind(kind).value)
    item = _get_item(subject, kind)
    if item is None:
        raise FileNotFoundError("encrypted document not found")
    blob = _get_blob(item, cipher)
    path = _safe_path(blob.path)
    _check_cipher(blob, path)
    return dek, _context(item), blob, path


def verify_item(subject: User, kind: ItemKind | str, cipher: str,
                actor: User) -> SecretBlob:
    dek, context, blob, path = _read_target(subject, kind, cipher, actor)
    with path.open("rb") as f:
        verify_stream(dek, context, f)
    return blob


def open_item(subject: User, kind: ItemKind | str, cipher: str,
              actor: User) -> Iterator[bytes]:
    dek, context, _blob, path = _read_target(subject, kind, cipher, actor)
    def _chunks() -> Iterator[bytes]:
        with path.open("rb") as f:
            yield from decrypt_stream(dek, context, f)
    return _chunks()


def load_bytes(subject: User, kind: ItemKind | str, actor: User,
               cipher: str | None = None) -> bytes | None:
    if _get_item(subject, kind) is None:
        # Still authorize to avoid letting callers probe the existence of items.
        unwrap_dek(subject, actor, _kind(kind).value)
        return None
    selected = cipher or settings.read_cipher
    verify_item(subject, kind, selected, actor)
    return b"".join(open_item(subject, kind, selected, actor))


def shred_user(subject: User, actor: User) -> None:
    """Delete active blobs and the wrapped DEK; does not erase external backups.

    Owner approval for an unassigned former tenant requires a separately
    authorized deletion workflow; do not bypass can_view_subject here.
    """
    db = _session(subject)
    # Only an owner handling an existing deletion request may shred data.
    # This also allows approval after move-out when the owner_id was recorded.
    # A request with no owner at all (tenant had moved out) is decided by the admin.
    # Shredding never unwraps the DEK, so the admin still can't read anything.
    if subject.role != Role.tenant:
        raise PermissionError("not authorized")
    if actor.role == Role.owner:
        decider = DeletionRequest.owner_id == actor.id
    elif actor.role == Role.admin:
        decider = DeletionRequest.owner_id.is_(None)
    else:
        raise PermissionError("not authorized")
    request = db.scalar(select(DeletionRequest).where(
        DeletionRequest.tenant_id == subject.id,
        decider,
        DeletionRequest.status.in_([DeletionStatus.pending, DeletionStatus.approved])))
    if request is None:
        raise PermissionError("no authorized deletion request")
    paths = []
    for item in list(db.scalars(select(SecretItem).where(SecretItem.subject_id == subject.id))):
        for blob in list(db.scalars(select(SecretBlob).where(SecretBlob.item_id == item.id))):
            paths.append(_safe_path(blob.path))
        db.delete(item)  # cascade deletes secret_blobs
    destroy_dek(subject)
    request.status = DeletionStatus.done
    db.commit()
    for path in paths:
        path.unlink(missing_ok=True)
    folder = settings.storage_dir.resolve() / str(subject.id)
    if folder.exists() and not any(folder.iterdir()):
        folder.rmdir()
