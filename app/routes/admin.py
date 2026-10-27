"""Admin: accounts and audit log. Deliberately has no route that touches documents."""
import secrets

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.auth.deps import require_role
from app.auth.security import csrf_protect, hash_password
from app.crypto.keys import create_dek
from app.db import get_db
from app.models import AuditLog, Role, User
from app.services import audit
from app.web import flash, redirect, render

router = APIRouter(prefix="/admin", dependencies=[Depends(csrf_protect)])
admin_only = require_role(Role.admin)


def _users_page(request: Request, db: Session, **extra):
    users = db.scalars(select(User).order_by(User.id)).all()
    return render(request, "admin/users.html", users=users, **extra)


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
                me: User = Depends(admin_only), db: Session = Depends(get_db)):
    email = email.strip().lower()
    if role not in (Role.owner.value, Role.tenant.value):
        flash(request, "err", "Role must be owner or tenant.")
        return redirect("/admin/users")
    if "@" not in email or len(email) > 255:
        flash(request, "err", "Enter a valid email address.")
        return redirect("/admin/users")
    if db.scalar(select(User.id).where(User.email == email)):
        flash(request, "err", "An account with that email already exists.")
        return redirect("/admin/users")
    temp = secrets.token_urlsafe(9)
    user = User(email=email, password_hash=hash_password(temp), role=Role(role),
                must_change_password=True)
    db.add(user)
    db.flush()
    if user.role == Role.tenant:
        create_dek(user)
    db.commit()
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


@router.get("/audit")
def audit_log(request: Request, failed: bool = False, me: User = Depends(admin_only),
              db: Session = Depends(get_db)):
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(200)
    if failed:
        query = query.where(AuditLog.ok.is_(False))
    emails = dict(db.execute(select(User.id, User.email)).all())
    return render(request, "admin/audit.html", entries=db.scalars(query).all(),
                  emails=emails, failed=failed)
