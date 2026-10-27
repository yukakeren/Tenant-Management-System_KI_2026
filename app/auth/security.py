"""Password hashing, CSRF tokens and the login rate limit."""
import hmac
import secrets
import time
from collections import defaultdict, deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import HTTPException, Request

_ph = PasswordHasher()  # argon2id, library defaults
# Verified against when the email doesn't exist, so both cases take the same time
_DUMMY_HASH = _ph.hash("kosanku-timing-dummy")

MIN_PASSWORD_LEN = 10


def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        _ph.verify(password_hash or _DUMMY_HASH, password)
    except (VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def check_csrf(request: Request, token: str | None) -> None:
    expected = request.session.get("csrf")
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise HTTPException(403, "Invalid or missing CSRF token. Reload the page and try again.")


async def csrf_protect(request: Request) -> None:
    """Router dependency: every POST must carry the session's token in a `csrf` form field."""
    if request.method != "POST":
        return
    token = (await request.form()).get("csrf")
    check_csrf(request, token if isinstance(token, str) else None)


# shortcut: in-memory and per-process, resets on restart; move to the DB or Redis if we run several workers.
MAX_LOGIN_FAILS = 5
LOGIN_WINDOW_S = 5 * 60
_FAILS: dict[str, deque[float]] = defaultdict(deque)


def login_blocked(ip: str) -> bool:
    fails, now = _FAILS[ip], time.monotonic()
    while fails and now - fails[0] > LOGIN_WINDOW_S:
        fails.popleft()
    return len(fails) >= MAX_LOGIN_FAILS


def record_login_fail(ip: str) -> None:
    _FAILS[ip].append(time.monotonic())
