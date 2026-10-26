"""
Tenant routes: profile, document uploads (RC4), view documents, and deletion requests.
"""

import os
import json
import time
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, UploadFile, status
from fastapi.responses import HTMLResponse, StreamingResponse
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
from app.services.upload import validate_and_read_upload
from app.crypto.rc4 import RC4Drop3072Cipher

router = APIRouter(prefix="/tenant", tags=["tenant"])

# Direktori lokal penyimpanan ciphertext
STORAGE_DIR = os.getenv("STORAGE_DIR", "storage/vault")
os.makedirs(STORAGE_DIR, exist_ok=True)


def get_current_tenant(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = None
    if "session" in request.scope:
        user_id = request.scope["session"].get("user_id")
    
    if not user_id:
        user_id = request.headers.get("X-User-Id")

    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Autentikasi dibutuhkan. Silakan login terlebih dahulu.",
        )

    user = db.scalar(select(User).where(User.id == int(user_id)))
    if not user or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User tidak valid.")

    if user.role != Role.tenant:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses khusus tenant.")

    return user


def get_user_dek(user: User) -> bytes:
    if user.wrapped_dek:
        return user.wrapped_dek[:32].ljust(32, b"\x00")
    return f"kosanku_dek_{user.id}".encode().ljust(32, b"\x00")

@router.get("/profile")
def view_profile(user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    item = db.scalar(
        select(SecretItem).where(
            SecretItem.subject_id == user.id,
            SecretItem.kind == ItemKind.profile,
        )
    )

    if not item:
        return {"email": user.email, "profile": None}

    blob = db.scalar(
        select(SecretBlob).where(
            SecretBlob.item_id == item.id,
            SecretBlob.cipher == CipherName.rc4,
        )
    )
    if not blob or not os.path.exists(blob.path):
        return {"email": user.email, "profile": None}

    with open(blob.path, "rb") as f:
        file_bytes = f.read()
    
    nonce = file_bytes[:16]
    tag = file_bytes[16:48]
    ciphertext = file_bytes[48:]
    dek = get_user_dek(user)

    plain_bytes = RC4Drop3072Cipher.decrypt(nonce, ciphertext, tag, dek)
    profile_data = json.loads(plain_bytes.decode("utf-8"))

    return {"email": user.email, "profile": profile_data}


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
        "full_name": full_name,
        "nik": nik,
        "phone": phone,
        "emergency": {
            "name": emergency_contact_name,
            "phone": emergency_contact_phone,
            "relation": emergency_relation,
        },
    }
    plain_bytes = json.dumps(profile_dict).encode("utf-8")
    dek = get_user_dek(user)

    start_t = time.perf_counter()
    nonce, ciphertext, tag = RC4Drop3072Cipher.encrypt(plain_bytes, dek)
    enc_ms = (time.perf_counter() - start_t) * 1000

    payload = nonce + tag + ciphertext
    filename = f"user_{user.id}_profile.rc4.bin"
    file_path = os.path.join(STORAGE_DIR, filename)
    with open(file_path, "wb") as f:
        f.write(payload)

    item = db.scalar(
        select(SecretItem).where(
            SecretItem.subject_id == user.id,
            SecretItem.kind == ItemKind.profile,
        )
    )
    if not item:
        item = SecretItem(
            subject_id=user.id,
            kind=ItemKind.profile,
            mime="application/json",
            plain_size=len(plain_bytes),
        )
        db.add(item)
        db.flush()
    else:
        item.plain_size = len(plain_bytes)

    blob = db.scalar(
        select(SecretBlob).where(
            SecretBlob.item_id == item.id,
            SecretBlob.cipher == CipherName.rc4,
        )
    )
    if not blob:
        blob = SecretBlob(
            item_id=item.id,
            cipher=CipherName.rc4,
            path=file_path,
            ct_size=len(payload),
            enc_ms=enc_ms,
        )
        db.add(blob)
    else:
        blob.path = file_path
        blob.ct_size = len(payload)
        blob.enc_ms = enc_ms

    db.commit()
    return {"status": "success", "message": "Profil berhasil diperbarui dan dienkripsi."}


@router.post("/upload/{doc_type}")
async def upload_document(
    doc_type: str,
    file: UploadFile,
    user: User = Depends(get_current_tenant),
    db: Session = Depends(get_db),
):
    filename, plain_bytes = await validate_and_read_upload(file, doc_type)

    # Map to ItemKind
    kind_map = {
        "ktp": ItemKind.ktp,
        "agreement": ItemKind.agreement,
        "video": ItemKind.video,
    }
    target_kind = kind_map[doc_type]

    dek = get_user_dek(user)
    start_t = time.perf_counter()
    nonce, ciphertext, tag = RC4Drop3072Cipher.encrypt(plain_bytes, dek)
    enc_ms = (time.perf_counter() - start_t) * 1000

    payload = nonce + tag + ciphertext
    out_filename = f"user_{user.id}_{doc_type}.rc4.bin"
    file_path = os.path.join(STORAGE_DIR, out_filename)
    with open(file_path, "wb") as f:
        f.write(payload)

    item = db.scalar(
        select(SecretItem).where(
            SecretItem.subject_id == user.id,
            SecretItem.kind == target_kind,
        )
    )
    if not item:
        item = SecretItem(
            subject_id=user.id,
            kind=target_kind,
            mime=file.content_type or "application/octet-stream",
            plain_size=len(plain_bytes),
        )
        db.add(item)
        db.flush()
    else:
        item.mime = file.content_type or item.mime
        item.plain_size = len(plain_bytes)

    blob = db.scalar(
        select(SecretBlob).where(
            SecretBlob.item_id == item.id,
            SecretBlob.cipher == CipherName.rc4,
        )
    )
    if not blob:
        blob = SecretBlob(
            item_id=item.id,
            cipher=CipherName.rc4,
            path=file_path,
            ct_size=len(payload),
            enc_ms=enc_ms,
        )
        db.add(blob)
    else:
        blob.path = file_path
        blob.ct_size = len(payload)
        blob.enc_ms = enc_ms

    log = AuditLog(
        actor_id=user.id,
        action=f"upload_{doc_type}",
        target_type="secret_item",
        target_id=item.id,
        ok=True,
        detail=f"Encrypted with RC4 ({len(plain_bytes)} bytes)",
    )
    db.add(log)
    db.commit()

    return {
        "status": "success",
        "doc_type": doc_type,
        "filename": filename,
        "plain_size": len(plain_bytes),
        "encryption_time_ms": round(enc_ms, 2),
    }


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
        raise HTTPException(status_code=400, detail="Tipe dokumen tidak valid")

    item = db.scalar(
        select(SecretItem).where(
            SecretItem.subject_id == user.id,
            SecretItem.kind == target_kind,
        )
    )
    if not item:
        raise HTTPException(status_code=404, detail="Dokumen tidak ditemukan")

    blob = db.scalar(
        select(SecretBlob).where(
            SecretBlob.item_id == item.id,
            SecretBlob.cipher == CipherName.rc4,
        )
    )
    if not blob or not os.path.exists(blob.path):
        raise HTTPException(status_code=404, detail="File terenkripsi tidak ditemukan di storage")

    with open(blob.path, "rb") as f:
        file_bytes = f.read()

    nonce = file_bytes[:16]
    tag = file_bytes[16:48]
    ciphertext = file_bytes[48:]
    dek = get_user_dek(user)

    decrypted_bytes = RC4Drop3072Cipher.decrypt(nonce, ciphertext, tag, dek)

    return StreamingResponse(
        io.BytesIO(decrypted_bytes),
        media_type=item.mime,
        headers={"Content-Disposition": f'attachment; filename="{kind}_download"'},
    )


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