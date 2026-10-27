"""Owner: kos and rooms, tenants and their documents, deletion approvals.

Every lookup goes through the get_owned_*_or_404 helpers, so another owner's ids give 404.
"""
import json

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
from app.models import DeletionRequest, ItemKind, Kos, Role, Room, SecretItem, User
from app.services import audit, deletion
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


def _kos_fields_ok(request: Request, name: str, address: str) -> bool:
    if not name or not address or len(name) > 120 or len(address) > 255:
        flash(request, "err", "Name (max 120) and address (max 255) are required.")
        return False
    return True


@router.post("/kos")
def create_kos(request: Request, name: str = Form(...), address: str = Form(...),
               me: User = Depends(owner_only), db: Session = Depends(get_db)):
    name, address = name.strip(), address.strip()
    if not _kos_fields_ok(request, name, address):
        return redirect("/owner/kos")
    kos = Kos(owner_id=me.id, name=name, address=address)
    db.add(kos)
    db.commit()
    audit.log(db, me, "create_kos", "kos", kos.id)
    flash(request, "ok", f"Added {name}.")
    return redirect("/owner/kos")


@router.post("/kos/{kos_id}/edit")
def edit_kos(request: Request, kos_id: int, name: str = Form(...), address: str = Form(...),
             me: User = Depends(owner_only), db: Session = Depends(get_db)):
    kos = get_owned_kos_or_404(db, me, kos_id)
    name, address = name.strip(), address.strip()
    if _kos_fields_ok(request, name, address):
        kos.name, kos.address = name, address
        db.commit()
        audit.log(db, me, "edit_kos", "kos", kos.id)
        flash(request, "ok", "Kos updated.")
    return redirect(f"/owner/kos/{kos.id}/rooms")


@router.post("/kos/{kos_id}/delete")
def delete_kos(request: Request, kos_id: int, me: User = Depends(owner_only),
               db: Session = Depends(get_db)):
    kos = get_owned_kos_or_404(db, me, kos_id)
    if any(r.tenant_id is not None for r in kos.rooms):
        flash(request, "err", "Move all tenants out before deleting this kos.")
        return redirect(f"/owner/kos/{kos.id}/rooms")
    db.delete(kos)  # its rooms go with it
    db.commit()
    audit.log(db, me, "delete_kos", "kos", kos_id)
    flash(request, "ok", f"Deleted {kos.name}.")
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
    return render(request, "deletion_requests.html", rows=rows, base=BASE)


BASE = "/owner/deletion-requests"


def _pending_request(db: Session, me: User, request_id: int) -> tuple[DeletionRequest, User]:
    req = get_owned_deletion_request_or_404(db, me, request_id)
    return req, deletion.tenant_of_pending(db, req)


@router.get("/deletion-requests/{request_id}/approve")
def confirm_approve(request: Request, request_id: int, me: User = Depends(owner_only),
                    db: Session = Depends(get_db)):
    req, tenant = _pending_request(db, me, request_id)
    return render(request, "confirm_deletion.html", req=req, tenant=tenant, base=BASE,
                  confirm_word=deletion.confirm_word(tenant))


@router.post("/deletion-requests/{request_id}/approve")
def approve_deletion(request: Request, request_id: int, confirm: str = Form(""),
                     me: User = Depends(owner_only), db: Session = Depends(get_db)):
    req, tenant = _pending_request(db, me, request_id)
    if confirm.strip() != deletion.confirm_word(tenant):
        flash(request, "err", "The confirmation didn't match. Nothing was deleted.")
        return redirect(f"{BASE}/{req.id}/approve")
    deletion.approve(db, req, tenant, me)
    flash(request, "ok", f"All of {tenant.email}'s documents and their key were deleted.")
    return redirect(BASE)


@router.post("/deletion-requests/{request_id}/reject")
def reject_deletion(request: Request, request_id: int, reason: str = Form(""),
                    me: User = Depends(owner_only), db: Session = Depends(get_db)):
    req, tenant = _pending_request(db, me, request_id)
    if not reason.strip():
        flash(request, "err", "Give a reason so the tenant knows why.")
        return redirect(BASE)
    deletion.reject(db, req, tenant, me, reason.strip())
    flash(request, "ok", "Request rejected.")
    return redirect(BASE)
