"""
Tenant routes: profile, document uploads, my documents, and deletion requests.
Every route works on the logged-in tenant only, so there are no ids in the URLs.
"""

import json
import re
from datetime import date, datetime, timezone

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from app.auth.deps import require_role
from app.auth.security import csrf_protect
from app.config import CIPHERS, settings
from app.crypto import vault
from app.crypto.base import IntegrityError
from app.db import get_db
from app.models import DeletionRequest, DeletionStatus, ItemKind, Role, SecretItem, User
from app.services import audit
from app.services.documents import DOC_KINDS, stream_document
from app.services.upload import DOCUMENT_SPECS, validate_upload_stream
from app.web import flash, redirect, render

router = APIRouter(prefix="/tenant", dependencies=[Depends(csrf_protect)])
get_current_tenant = require_role(Role.tenant)

PROFILE_FIELDS = ("full_name", "nik", "birth_date", "gender", "phone", "origin_address", "occupation")
EMERGENCY_FIELDS = ("name", "relation", "phone")
GENDERS = ("male", "female")
_PHONE = re.compile(r"\+?\d{8,15}")


def _items(db: Session, user: User) -> dict[str, SecretItem]:
    items = db.scalars(select(SecretItem).where(SecretItem.subject_id == user.id)).all()
    return {it.kind.value: it for it in items}


@router.get("")
def home(request: Request, user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    return render(request, "tenant/home.html", room=user.room, items=_items(db, user),
                  kinds=("profile",) + DOC_KINDS)


def _validate_profile(form: dict[str, str]) -> list[str]:
    errors = [f"{name.replace('_', ' ').capitalize()} is required."
              for name, value in form.items() if not value]
    if any(len(v) > 200 for v in form.values()):
        errors.append("Each field can be at most 200 characters.")
    if form["nik"] and not re.fullmatch(r"\d{16}", form["nik"]):
        errors.append("NIK must be exactly 16 digits.")
    for key in ("phone", "ec_phone"):
        if form[key] and not _PHONE.fullmatch(form[key]):
            errors.append("Phone numbers may only contain digits and a leading +, 8 to 15 digits.")
    if form["gender"] and form["gender"] not in GENDERS:
        errors.append("Pick a gender from the list.")
    if form["birth_date"]:
        try:
            if date.fromisoformat(form["birth_date"]) >= date.today():
                errors.append("Birth date must be in the past.")
        except ValueError:
            errors.append("Birth date is not a valid date.")
    return errors


@router.get("/profile")
def view_profile(request: Request, user: User = Depends(get_current_tenant)):
    try:
        data = vault.load_bytes(user, ItemKind.profile, user)
    except IntegrityError:
        flash(request, "err", "Your saved profile failed its integrity check. Please fill it in again.")
        data = None
    profile = json.loads(data) if data is not None else {}
    form = {k: profile.get(k, "") for k in PROFILE_FIELDS}
    form.update({f"ec_{k}": profile.get("emergency_contact", {}).get(k, "") for k in EMERGENCY_FIELDS})
    return render(request, "tenant/profile.html", form=form, genders=GENDERS)


@router.post("/profile")
async def update_profile(request: Request, user: User = Depends(get_current_tenant),
                         db: Session = Depends(get_db)):
    data = await request.form()
    keys = PROFILE_FIELDS + tuple(f"ec_{k}" for k in EMERGENCY_FIELDS)
    form = {k: str(data.get(k, "")).strip() for k in keys}
    errors = _validate_profile(form)
    if errors:
        return render(request, "tenant/profile.html", status_code=400, form=form,
                      genders=GENDERS, errors=errors)
    profile = {k: form[k] for k in PROFILE_FIELDS}
    profile["emergency_contact"] = {k: form[f"ec_{k}"] for k in EMERGENCY_FIELDS}
    await run_in_threadpool(vault.store_bytes, user, ItemKind.profile,
                            json.dumps(profile).encode("utf-8"), user)
    audit.log(db, user, "update_profile", "user", user.id)
    flash(request, "ok", "Profile saved and encrypted.")
    return redirect("/tenant")


def _documents_page(request: Request, db: Session, user: User, status_code: int = 200, error=None):
    return render(request, "tenant/documents.html", status_code=status_code, items=_items(db, user),
                  kinds=DOC_KINDS, specs=DOCUMENT_SPECS, ciphers=CIPHERS, error=error)


@router.get("/documents")
def list_documents(request: Request, user: User = Depends(get_current_tenant),
                   db: Session = Depends(get_db)):
    return _documents_page(request, db, user)


@router.post("/documents/{kind}")
async def upload_document(request: Request, kind: str, file: UploadFile = File(...),
                          user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    if kind not in DOC_KINDS:
        raise HTTPException(404, "Unknown document type.")
    try:
        _, size = await run_in_threadpool(validate_upload_stream, file, kind)
        await run_in_threadpool(vault.store_item, user, kind, file.file, file.content_type, user)
    except HTTPException as e:
        return _documents_page(request, db, user, status_code=e.status_code, error=e.detail)
    finally:
        await file.close()  # deletes FastAPI's plaintext temp file right away
    audit.log(db, user, "upload", "user", user.id, detail=f"{kind} ({size} bytes)")
    flash(request, "ok", "Uploaded and encrypted with AES, DES and RC4.")
    return redirect("/tenant/documents")


@router.get("/documents/{kind}")
def download_document(kind: str, cipher: str = settings.read_cipher,
                      user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    return stream_document(db, user, kind, cipher, user)


def _latest_request(db: Session, user: User) -> DeletionRequest | None:
    return db.scalar(select(DeletionRequest).where(DeletionRequest.tenant_id == user.id)
                     .order_by(DeletionRequest.id.desc()))


@router.get("/deletion-request")
def deletion_status(request: Request, user: User = Depends(get_current_tenant),
                    db: Session = Depends(get_db)):
    return render(request, "tenant/deletion.html", req=_latest_request(db, user), room=user.room)


@router.post("/deletion-request")
def request_deletion(request: Request, reason: str = Form(""),
                     user: User = Depends(get_current_tenant), db: Session = Depends(get_db)):
    latest = _latest_request(db, user)
    if latest is not None and latest.status == DeletionStatus.pending:
        flash(request, "err", "You already have a pending request.")
        return redirect("/tenant/deletion-request")
    room = user.room
    req = DeletionRequest(tenant_id=user.id, owner_id=room.kos.owner_id if room else None,
                          reason=reason.strip()[:1000])
    db.add(req)
    db.commit()
    audit.log(db, user, "request_deletion", "user", user.id)
    if req.owner_id is not None:
        flash(request, "ok", "Request sent. Your kos owner has to approve it.")
        return redirect("/tenant/deletion-request")
    # Moved out and nobody to approve: approved automatically
    vault.shred_user(user, user)
    user.is_active = False
    req.decided_by = user.id
    req.decided_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, user, "approve_deletion", "user", user.id, detail="auto, no owner")
    request.session.clear()
    flash(request, "ok", "All your documents and your key were deleted, and your account was closed.")
    return redirect("/login")
