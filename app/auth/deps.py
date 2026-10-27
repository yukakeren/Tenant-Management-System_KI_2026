from fastapi import Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Role, User

# Pages a user with must_change_password may still open
_FORCED_CHANGE_ALLOWED = {"/account/password", "/logout"}


def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if user_id else None
    if user is None or not user.is_active:
        request.session.pop("user_id", None)
        raise HTTPException(401)
    if user.must_change_password and request.url.path not in _FORCED_CHANGE_ALLOWED:
        raise HTTPException(303, headers={"Location": "/account/password"})
    request.state.user = user
    return user


def require_role(*roles: Role):
    def dep(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(403, "You don't have access to this page.")
        return user
    return dep
