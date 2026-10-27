"""Shared template rendering and flash messages for all routers."""
from pathlib import Path

from fastapi import Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates

from .auth.security import new_csrf_token

templates = Jinja2Templates(directory=Path(__file__).parent / "templates")


def flash(request: Request, kind: str, msg: str) -> None:
    """kind is "ok" or "err". Shown once on the next rendered page."""
    request.session.setdefault("flashes", []).append([kind, msg])


def render(request: Request, name: str, status_code: int = 200, **ctx):
    request.session.setdefault("csrf", new_csrf_token())
    ctx.setdefault("user", getattr(request.state, "user", None))
    ctx["flashes"] = request.session.pop("flashes", [])
    return templates.TemplateResponse(request, name, ctx, status_code=status_code)


def redirect(url: str) -> RedirectResponse:
    return RedirectResponse(url, status_code=303)
