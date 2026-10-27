"""Owner: kos and rooms, tenants and their documents, deletion approvals.

Every lookup goes through the get_owned_*_or_404 helpers, so another owner's ids give 404.
"""
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError as DBIntegrityError
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.auth.security import csrf_protect
from app.config import CIPHERS, settings
from app.crypto import vault
from app.crypto.base import IntegrityError
from app.db import get_db
from app.models import DeletionRequest, DeletionStatus, ItemKind, Kos, Role, Room, SecretItem, User
from app.services import audit
from app.services.access import (
    get_owned_deletion_request_or_404, get_owned_kos_or_404, get_owned_room_or_404,
    get_owned_tenant_or_404,
)
from app.services.documents import stream_document
from app.web import flash, redirect, render

router = APIRouter(prefix="/owner", dependencies=[Depends(csrf_protect)])
owner_only = require_role(Role.owner)


@router.get("/kos")
def list_kos(request: Request, me: User = Depends(owner_only), db: Session = Depends(get_db)):
    kos_list = db.scalars(select(Kos).where(Kos.owner_id == me.id).order_by(Kos.id)).all()
    return render(request, "owner/kos.html", kos_list=kos_list)


@router.post("/kos")
def create_kos(request: Request, name: str = Form(...), address: str = Form(...),
               me: User = Depends(owner_only), db: Session = Depends(get_db)):
    name, address = name.strip(), address.strip()
    if not name or not address or len(name) > 120 or len(address) > 255:
        flash(request, "err", "Name (max 120) and address (max 255) are required.")
        return redirect("/owner/kos")
    kos = Kos(owner_id=me.id, name=name, address=address)
    db.add(kos)
    db.commit()
    audit.log(db, me, "create_kos", "kos", kos.id)
    flash(request, "ok", f"Added {name}.")
    return redirect("/owner/kos")


@router.get("/kos/{kos_id}/rooms")
def list_rooms(request: Request, kos_id: int, me: User = Depends(owner_only),
               db: Session = Depends(get_db)):
    kos = get_owned_kos_or_404(db, me, kos_id)
    rooms = sorted(kos.rooms, key=lambda r: r.number)
    return render(request, "owner/rooms.html", kos=kos, rooms=rooms)


@router.post("/kos/{kos_id}/rooms")
def create_room(request: Request, kos_id: int, number: str = Form(...),
                me: User = Depends(owner_only), db: Session = Depends(get_db)):
    kos = get_owned_kos_or_404(db, me, kos_id)
    number = number.strip()
    if not number or len(number) > 20:
        flash(request, "err", "Room number is required (max 20 characters).")
        return redirect(f"/owner/kos/{kos.id}/rooms")
    room = Room(kos_id=kos.id, number=number)
    db.add(room)
    try:
        db.commit()
    except DBIntegrityError:
        db.rollback()
        flash(request, "err", f"Room {number} already exists in this kos.")
        return redirect(f"/owner/kos/{kos.id}/rooms")
    audit.log(db, me, "create_room", "room", room.id)
    flash(request, "ok", f"Added room {number}.")
    return redirect(f"/owner/kos/{kos.id}/rooms")


@router.post("/rooms/{room_id}/assign")
def assign_tenant(request: Request, room_id: int, email: str = Form(...),
                  me: User = Depends(owner_only), db: Session = Depends(get_db)):
    room = get_owned_room_or_404(db, me, room_id)
    back = f"/owner/kos/{room.kos_id}/rooms"
    if room.tenant_id is not None:
        flash(request, "err", f"Room {room.number} already has a tenant.")
        return redirect(back)
    tenant = db.scalar(select(User).where(User.email == email.strip().lower(),
                                          User.role == Role.tenant, User.is_active.is_(True)))
    if tenant is None:
        flash(request, "err", "No active tenant account with that email. Ask the admin to create it.")
        return redirect(back)
    if tenant.room is not None:
        flash(request, "err", "That tenant already has a room.")
        return redirect(back)
    room.tenant_id = tenant.id
    try:
        db.commit()
    except DBIntegrityError:  # someone assigned them at the same moment
        db.rollback()
        flash(request, "err", "That tenant already has a room.")
        return redirect(back)
    audit.log(db, me, "assign_tenant", "room", room.id)
    flash(request, "ok", f"Assigned {tenant.email} to room {room.number}.")
    return redirect(back)


@router.post("/rooms/{room_id}/unassign")
def unassign_tenant(request: Request, room_id: int, me: User = Depends(owner_only),
                    db: Session = Depends(get_db)):
    room = get_owned_room_or_404(db, me, room_id)
    # The tenant's data stays (they can still ask for deletion); our access ends right away
    room.tenant_id = None
    db.commit()
    audit.log(db, me, "unassign_tenant", "room", room.id)
    flash(request, "ok", f"Room {room.number} is now empty.")
    return redirect(f"/owner/kos/{room.kos_id}/rooms")


@router.get("/tenants")
def list_tenants(request: Request, me: User = Depends(owner_only), db: Session = Depends(get_db)):
    rows = db.execute(
        select(User, Room, Kos).join(Room, Room.tenant_id == User.id).join(Kos, Room.kos_id == Kos.id)
        .where(Kos.owner_id == me.id).order_by(Kos.name, Room.number)
    ).all()
    kinds: dict[int, set[str]] = {}
    for subject_id, kind in db.execute(select(SecretItem.subject_id, SecretItem.kind).where(
            SecretItem.subject_id.in_([u.id for u, _, _ in rows]))):
        kinds.setdefault(subject_id, set()).add(kind.value)
    return render(request, "owner/tenants.html", rows=rows, kinds=kinds)


@router.get("/tenants/{tenant_id}")
def show_tenant(request: Request, tenant_id: int, me: User = Depends(owner_only),
                db: Session = Depends(get_db)):
    tenant = get_owned_tenant_or_404(db, me, tenant_id)
    profile, profile_error = None, None
    try:
        data = vault.load_bytes(tenant, "profile", me)
        profile = json.loads(data) if data is not None else None
    except IntegrityError:
        audit.log(db, me, "view_profile", "user", tenant.id, ok=False, detail="integrity check failed")
        profile_error = "The profile failed its integrity check and was not shown."
    except (PermissionError, FileNotFoundError):
        raise HTTPException(404, "Tenant not found.") from None
    items = db.scalars(select(SecretItem).where(SecretItem.subject_id == tenant.id,
                                                SecretItem.kind != ItemKind.profile)).all()
    return render(request, "owner/tenant.html", tenant=tenant, profile=profile,
                  profile_error=profile_error, items=items, ciphers=CIPHERS)


@router.get("/tenants/{tenant_id}/documents/{kind}")
def download_document(tenant_id: int, kind: str, cipher: str = settings.read_cipher,
                      me: User = Depends(owner_only), db: Session = Depends(get_db)):
    tenant = get_owned_tenant_or_404(db, me, tenant_id)
    return stream_document(db, tenant, kind, cipher, me)


@router.get("/deletion-requests")
def list_deletion_requests(request: Request, me: User = Depends(owner_only),
                           db: Session = Depends(get_db)):
    rows = db.execute(
        select(DeletionRequest, User).join(User, User.id == DeletionRequest.tenant_id)
        .where(DeletionRequest.owner_id == me.id).order_by(DeletionRequest.id.desc())
    ).all()
    return render(request, "owner/deletion_requests.html", rows=rows)


def _pending_request(db: Session, me: User, request_id: int) -> tuple[DeletionRequest, User]:
    req = get_owned_deletion_request_or_404(db, me, request_id)
    if req.status != DeletionStatus.pending:
        raise HTTPException(400, "This request has already been decided.")
    return req, db.get(User, req.tenant_id)


def _confirm_word(tenant: User) -> str:
    # Typed back by the owner before an irreversible shred
    return tenant.room.number if tenant.room else tenant.email


@router.get("/deletion-requests/{request_id}/approve")
def confirm_approve(request: Request, request_id: int, me: User = Depends(owner_only),
                    db: Session = Depends(get_db)):
    req, tenant = _pending_request(db, me, request_id)
    return render(request, "owner/confirm_approve.html", req=req, tenant=tenant,
                  confirm_word=_confirm_word(tenant))


@router.post("/deletion-requests/{request_id}/approve")
def approve_deletion(request: Request, request_id: int, confirm: str = Form(""),
                     me: User = Depends(owner_only), db: Session = Depends(get_db)):
    req, tenant = _pending_request(db, me, request_id)
    if confirm.strip() != _confirm_word(tenant):
        flash(request, "err", "The confirmation didn't match. Nothing was deleted.")
        return redirect(f"/owner/deletion-requests/{req.id}/approve")
    room = tenant.room
    try:
        vault.shred_user(tenant, me)  # deletes files and DEK, marks the request done, commits
    except PermissionError:
        raise HTTPException(404, "Deletion request not found.") from None
    if room is not None:
        room.tenant_id = None
    tenant.is_active = False
    req.decided_by = me.id
    req.decided_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, me, "approve_deletion", "user", tenant.id)
    flash(request, "ok", f"All of {tenant.email}'s documents and their key were deleted.")
    return redirect("/owner/deletion-requests")


@router.post("/deletion-requests/{request_id}/reject")
def reject_deletion(request: Request, request_id: int, reason: str = Form(""),
                    me: User = Depends(owner_only), db: Session = Depends(get_db)):
    req, tenant = _pending_request(db, me, request_id)
    reason = reason.strip()
    if not reason:
        flash(request, "err", "Give a reason so the tenant knows why.")
        return redirect("/owner/deletion-requests")
    req.status = DeletionStatus.rejected
    req.reject_reason = reason[:1000]
    req.decided_by = me.id
    req.decided_at = datetime.now(timezone.utc)
    db.commit()
    audit.log(db, me, "reject_deletion", "user", tenant.id)
    flash(request, "ok", "Request rejected.")
    return redirect("/owner/deletion-requests")
