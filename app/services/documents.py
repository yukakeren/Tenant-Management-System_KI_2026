"""Verify-then-stream download, shared by the owner and tenant routes."""
import mimetypes

from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import CIPHERS
from app.crypto import vault
from app.crypto.base import IntegrityError
from app.models import ItemKind, SecretItem, User
from app.services import audit

DOC_KINDS = ("ktp", "agreement", "video")


def stream_document(db: Session, subject: User, kind: str, cipher: str, actor: User) -> StreamingResponse:
    """Caller must already have checked that actor may see subject (404 otherwise)."""
    if kind not in DOC_KINDS or cipher not in CIPHERS:
        raise HTTPException(404, "Document not found.")
    item = db.scalar(select(SecretItem).where(
        SecretItem.subject_id == subject.id, SecretItem.kind == ItemKind(kind)))
    if item is None:
        raise HTTPException(404, "Document not found.")
    try:
        # First pass checks every chunk, so a tampered file never starts streaming
        vault.verify_item(subject, kind, cipher, actor)
        chunks = vault.open_item(subject, kind, cipher, actor)
    except (PermissionError, FileNotFoundError):
        raise HTTPException(404, "Document not found.") from None
    except IntegrityError:
        audit.log(db, actor, "download", "user", subject.id, ok=False,
                  detail=f"{kind}/{cipher} failed integrity check")
        raise HTTPException(409, f"The {cipher.upper()} copy of this document failed its integrity "
                                 "check and was not returned. It may have been tampered with.") from None
    audit.log(db, actor, "download", "user", subject.id, detail=f"{kind}/{cipher}")
    filename = kind + (mimetypes.guess_extension(item.mime) or "")
    return StreamingResponse(chunks, media_type=item.mime,
                             headers={"Content-Disposition": f'attachment; filename="{filename}"'})
