"""Admin: accounts, audit log, and deletion requests that have no owner.

Deliberately has no route that reads documents. Approving a deletion shreds files and the
key without ever unwrapping it.
"""
import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError as DBIntegrityError
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.auth.security import csrf_protect, hash_password
from app.crypto.keys import create_dek
from app.db import get_db
from app.models import AuditLog, DeletionRequest, Kos, Role, Room, User
from app.services import audit, deletion
from app.web import flash, redirect, render

router = APIRouter(prefix="/admin", dependencies=[Depends(csrf_protect)])
admin_only = require_role(Role.admin)


def _users_page(request: Request, db: Session, **extra):
    users = db.scalars(select(User).order_by(User.id)).all()
    empty_rooms = db.execute(select(Room, Kos).join(Kos, Room.kos_id == Kos.id)
                             .where(Room.tenant_id.is_(None)).order_by(Kos.name, Room.number)).all()
    has_owner = any(u.role == Role.owner for u in users)
    return render(request, "admin/users.html", users=users, empty_rooms=empty_rooms,
                  has_owner=has_owner, **extra)


def _refuse(request: Request, msg: str):
    flash(request, "err", msg)
    return redirect("/admin/users")


def _target(db: Session, me: User, user_id: int) -> User:
    target = db.get(User, user_id)
    if target is None:
        raise HTTPException(404, "User not found.")
    if target.id == me.id:
        raise HTTPException(400, "You can't do this to your own account.")
    return target


@router.get("/users")
def list_users(request: Request, me: User = Depends(admin_only), db: Session = Depends(get_db)):
    return _users_page(request, db)


@router.post("/users")
def create_user(request: Request, email: str = Form(...), role: str = Form(...),
                room_id: int | None = Form(None), me: User = Depends(admin_only),
                db: Session = Depends(get_db)):
    """Tenants get their account after paying for a room, so a tenant is always created in one."""
    email = email.strip().lower()
    if role not in (Role.owner.value, Role.tenant.value):
        return _refuse(request, "Role must be owner or tenant.")
    if "@" not in email or len(email) > 255:
        return _refuse(request, "Enter a valid email address.")
    if db.scalar(select(User.id).where(User.email == email)):
        return _refuse(request, "An account with that email already exists.")
    room = None
    if role == Role.owner.value:
        if db.scalar(select(User.id).where(User.role == Role.owner)):
            return _refuse(request, "There is already an owner. KosanKu has exactly one owner.")
    else:
        room = db.get(Room, room_id) if room_id else None
        if room is None or room.tenant_id is not None:
            return _refuse(request, "Pick an empty room for the new tenant.")
    temp = secrets.token_urlsafe(9)
    user = User(email=email, password_hash=hash_password(temp), role=Role(role),
                must_change_password=True)
    db.add(user)
    db.flush()
    if room is not None:
        create_dek(user)
        room.tenant_id = user.id
    try:
        db.commit()
    except DBIntegrityError:  # the room was filled at the same moment
        db.rollback()
        return _refuse(request, "That room was just taken. Pick another one.")
    audit.log(db, me, "create_user", "user", user.id, detail=role)
    # Shown once in this response, never stored or logged
    return _users_page(request, db, temp_password=(email, temp))


@router.post("/users/{user_id}/reset-password")
def reset_password(request: Request, user_id: int, me: User = Depends(admin_only),
                   db: Session = Depends(get_db)):
    target = _target(db, me, user_id)
    temp = secrets.token_urlsafe(9)
    # The DEK is wrapped with MASTER_KEY, not the password, so documents survive this
    target.password_hash = hash_password(temp)
    target.must_change_password = True
    db.commit()
    audit.log(db, me, "reset_password", "user", target.id)
    return _users_page(request, db, temp_password=(target.email, temp))


@router.post("/users/{user_id}/toggle")
def toggle_user(request: Request, user_id: int, me: User = Depends(admin_only),
                db: Session = Depends(get_db)):
    target = _target(db, me, user_id)
    target.is_active = not target.is_active
    db.commit()
    audit.log(db, me, "activate_user" if target.is_active else "deactivate_user", "user", target.id)
    flash(request, "ok", f"{target.email} is now {'active' if target.is_active else 'inactive'}.")
    return redirect("/admin/users")


DELETIONS = "/admin/deletion-requests"


def _ownerless_pending(db: Session, request_id: int) -> tuple[DeletionRequest, User]:
    req = db.scalar(select(DeletionRequest).where(DeletionRequest.id == request_id,
                                                  DeletionRequest.owner_id.is_(None)))
    if req is None:
        raise HTTPException(404, "Deletion request not found.")
    return req, deletion.tenant_of_pending(db, req)


@router.get("/deletion-requests")
def list_deletion_requests(request: Request, me: User = Depends(admin_only),
                           db: Session = Depends(get_db)):
    rows = db.execute(
        select(DeletionRequest, User).join(User, User.id == DeletionRequest.tenant_id)
        .where(DeletionRequest.owner_id.is_(None)).order_by(DeletionRequest.id.desc())
    ).all()
    return render(request, "deletion_requests.html", rows=rows, base=DELETIONS)


@router.get("/deletion-requests/{request_id}/approve")
def confirm_approve(request: Request, request_id: int, me: User = Depends(admin_only),
                    db: Session = Depends(get_db)):
    req, tenant = _ownerless_pending(db, request_id)
    return render(request, "confirm_deletion.html", req=req, tenant=tenant, base=DELETIONS,
                  confirm_word=deletion.confirm_word(tenant))


@router.post("/deletion-requests/{request_id}/approve")
def approve_deletion(request: Request, request_id: int, confirm: str = Form(""),
                     me: User = Depends(admin_only), db: Session = Depends(get_db)):
    req, tenant = _ownerless_pending(db, request_id)
    if confirm.strip() != deletion.confirm_word(tenant):
        flash(request, "err", "The confirmation didn't match. Nothing was deleted.")
        return redirect(f"{DELETIONS}/{req.id}/approve")
    deletion.approve(db, req, tenant, me)
    flash(request, "ok", f"All of {tenant.email}'s documents and their key were deleted.")
    return redirect(DELETIONS)


@router.post("/deletion-requests/{request_id}/reject")
def reject_deletion(request: Request, request_id: int, reason: str = Form(""),
                    me: User = Depends(admin_only), db: Session = Depends(get_db)):
    req, tenant = _ownerless_pending(db, request_id)
    if not reason.strip():
        flash(request, "err", "Give a reason so the tenant knows why.")
        return redirect(DELETIONS)
    deletion.reject(db, req, tenant, me, reason.strip())
    flash(request, "ok", "Request rejected.")
    return redirect(DELETIONS)


@router.get("/audit")
def audit_log(request: Request, failed: bool = False, me: User = Depends(admin_only),
              db: Session = Depends(get_db)):
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(200)
    if failed:
        query = query.where(AuditLog.ok.is_(False))
    emails = dict(db.execute(select(User.id, User.email)).all())
    return render(request, "admin/audit.html", entries=db.scalars(query).all(),
                  emails=emails, failed=failed)
