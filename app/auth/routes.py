from fastapi import APIRouter, Depends, Form, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Role, User
from app.services import audit
from app.web import flash, redirect, render
from .deps import current_user
from .security import (
    MIN_PASSWORD_LEN, csrf_protect, hash_password, login_blocked, new_csrf_token,
    record_login_fail, verify_password,
)

router = APIRouter(dependencies=[Depends(csrf_protect)])

HOME = {Role.admin: "/admin/users", Role.owner: "/owner/kos", Role.tenant: "/tenant"}


@router.get("/")
def index(request: Request, db: Session = Depends(get_db)):
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    if user and user.is_active:
        return redirect(HOME[user.role])
    return render(request, "index.html")


@router.get("/login")
def login_form(request: Request):
    return render(request, "login.html")


@router.post("/login")
def login(request: Request, email: str = Form(...), password: str = Form(...),
          db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    if login_blocked(ip):
        return render(request, "login.html", status_code=429, email=email,
                      error="Too many failed attempts. Try again in a few minutes.")
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if not verify_password(user.password_hash if user else None, password) or not user.is_active:
        record_login_fail(ip)
        audit.log(db, None, "login", "user", user.id if user else None, ok=False)
        # Same message for unknown email, wrong password and inactive account
        return render(request, "login.html", status_code=400, email=email,
                      error="Wrong email or password.")
    request.session.clear()
    request.session.update(user_id=user.id, csrf=new_csrf_token())
    audit.log(db, user, "login", "user", user.id)
    return redirect("/account/password" if user.must_change_password else HOME[user.role])


@router.post("/logout")
def logout(request: Request):
    request.session.clear()
    return redirect("/login")


@router.get("/account/password")
def password_form(request: Request, user: User = Depends(current_user)):
    return render(request, "change_password.html")


@router.post("/account/password")
def change_password(request: Request, old_password: str = Form(...), new_password: str = Form(...),
                    confirm_password: str = Form(...), user: User = Depends(current_user),
                    db: Session = Depends(get_db)):
    if not verify_password(user.password_hash, old_password):
        error = "Your current password is wrong."
    elif len(new_password) < MIN_PASSWORD_LEN:
        error = f"The new password must be at least {MIN_PASSWORD_LEN} characters."
    elif new_password != confirm_password:
        error = "The two new passwords don't match."
    elif new_password == old_password:
        error = "The new password must be different from the current one."
    else:
        error = None
    if error:
        return render(request, "change_password.html", status_code=400, error=error)
    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()
    audit.log(db, user, "change_password", "user", user.id)
    flash(request, "ok", "Password changed.")
    return redirect(HOME[user.role])
