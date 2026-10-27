"""
Tenant routes: profile, document uploads (RC4), view documents, and deletion requests.
"""

import os
import json
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, StreamingResponse
from starlette.concurrency import run_in_threadpool
import io
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.db import get_db
from app.models import (
    User,
    Role,
    Room,
    SecretItem,
    SecretBlob,
    ItemKind,
    CipherName,
    DeletionRequest,
    DeletionStatus,
    AuditLog,
)
from app.services.upload import validate_upload_stream
from app.crypto import vault
from app.crypto.base import IntegrityError
from app.config import settings

router = APIRouter(prefix="/tenant", tags=["tenant"])

# Direktori lokal penyimpanan ciphertext
STORAGE_DIR = os.getenv("STORAGE_DIR", "storage/vault")
os.makedirs(STORAGE_DIR, exist_ok=True)


def get_current_tenant(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = None
    if "session" in request.scope:
        user_id = request.scope["session"].get("user_id")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi dibutuhkan. Silakan login terlebih dahulu.",
        )

    user = db.scalar(select(User).where(User.id == int(user_id)))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usertidak valid.")

    if user.role != Role.tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses khusus tenant.")

    return user


@router.get("/profile")
def view_profile(user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    try:
        data = vault.load_bytes(user, ItemKind.profile, user)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Akses ditolak") from None
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Integritas dokumen gagal") from None
    except (FileNotFoundError, OSError):
        raise HTTPException(status_code=404, detail="Profil terenkripsi tidak ditemukan") from None
    return {"email": user.email, "profile": json.loads(data) if data is not None else None}


@router.post("/profile")
def update_profile(
    full_name: str = Form(...),
    nik: str = Form(...),
    phone: str = Form(...),
    emergency_contact_name: str = Form(...),
    emergency_contact_phone: str = Form(...),
    emergency_relation: str = Form(...),
    user: User = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    profile_dict = {
        "full_name": full_name, "nik": nik, "phone": phone,
        "emergency": {
            "name": emergency_contact_name,
            "phone": emergency_contact_phone,
            "relation": emergency_relation,
        },
    }
    try:
        vault.store_bytes(user, ItemKind.profile, json.dumps(profile_dict).encode("utf-8"), user)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Akses ditolak") from None
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Integritas dokumen gagal") from None
    return {"status": "success", "message": "Profil berhasil diperbarui dan dienkripsi."}


@router.post("/upload/{doc_type}")
async def upload_document(
    doc_type: str,
    file: UploadFile,
    user: User = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    filename, plain_size = await run_in_threadpool(validate_upload_stream, file, doc_type)
    kind_map = {"ktp": ItemKind.ktp, "agreement": ItemKind.agreement, "video": ItemKind.video}
    try:
        item = await run_in_threadpool(
            vault.store_item,
            user,
            kind_map[doc_type],
            file.file,
            file.content_type or "application/octet-stream",
            user,
        )
    except PermissionError:
        raise HTTPException(status_code=403, detail="Akses ditolak") from None
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Integritas dokumen gagal") from None
    db.add(AuditLog(actor_id=user.id, action=f"upload_{doc_type}",
                    target_type="secret_item", target_id=item.id, ok=True,
                    detail=f"Encrypted with AES, DES, RC4 ({plain_size} bytes)"))
    db.commit()
    return {"status": "success", "doc_type": doc_type,
            "filename": filename, "plain_size": plain_size}


@router.get("/documents")
def list_documents(user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    items = db.scalars(select(SecretItem).where(SecretItem.subject_id == user.id)).all()
    results = []
    for it in items:
        results.append(
            {
                "id": it.id,
                "kind": it.kind.value,
                "mime": it.mime,
                "plain_size": it.plain_size,
                "created_at": it.created_at.isoformat(),
            }
        )
    return {"documents": results}


@router.get("/documents/{kind}/download")
def download_document(
    kind: str,
    user: User = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    try:
        target_kind = ItemKind(kind)
    except ValueError:
        raise HTTPException(status_code=400, detail="Tipe dokumen tidak valid") from None
    item = db.scalar(select(SecretItem).where(
        SecretItem.subject_id == user.id, SecretItem.kind == target_kind))
    if item is None:
        raise HTTPException(status_code=404, detail="Dokumen tidak ditemukan")
    try:
        vault.verify_item(user, target_kind, settings.read_cipher, user)
        content = vault.open_item(user, target_kind, settings.read_cipher, user)
    except PermissionError:
        raise HTTPException(status_code=403, detail="Akses ditolak") from None
    except IntegrityError:
        raise HTTPException(status_code=409, detail="Integritas dokumen gagal") from None
    except (FileNotFoundError, OSError):
        raise HTTPException(status_code=404, detail="File terenkripsi tidak ditemukan") from None
    return StreamingResponse(content, media_type=item.mime,
                             headers={"Content-Disposition": f'attachment; filename="{kind}_download"'})


@router.post("/deletion-request")
def request_deletion(
    reason: str = Form(...),
    user: User = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    room = db.scalar(select(Room).where(Room.tenant_id == user.id))
    owner_id = room.kos.owner_id if (room and room.kos) else None

    req = DeletionRequest(
        tenant_id=user.id,
        owner_id=owner_id,
        reason=reason,
        status=DeletionStatus.pending,
    )
    db.add(req)

    db.add(
        AuditLog(
            actor_id=user.id,
            action="request_deletion",
            target_type="user",
            target_id=user.id,
            ok=True,
            detail="Tenant submitted deletion request",
        )
    )
    db.commit()

    return {
        "status": "success",
        "message": "Permohonan penghapusan telah diajukan. Menunggu persetujuan pemilik kos.",
        "request_id": req.id,
    }
