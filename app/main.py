from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from .auth import routes as auth
from .config import settings
from .db import init_db
from .routes import admin, owner, tenant
from .web import redirect, render, templates

BASE_DIR = Path(__file__).parent

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'self'",
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    yield


async def http_error(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 401:
        return redirect("/login")
    if 300 <= exc.status_code < 400:
        return redirect(exc.headers["Location"])
    return render(request, "error.html", status_code=exc.status_code, code=exc.status_code,
                  detail=exc.detail)


async def validation_error(request: Request, exc: RequestValidationError):
    return render(request, "error.html", status_code=400, code=400,
                  detail="Some form fields are missing or invalid.")


async def server_error(request: Request, exc: Exception):
    # Runs outside SessionMiddleware, so no render(); never shows a stack trace
    return templates.TemplateResponse(request, "error.html", {
        "code": 500, "detail": "Something went wrong on our side.", "user": None, "flashes": []},
        status_code=500)


def create_app() -> FastAPI:
    app = FastAPI(title="KosanKu", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.hex(),
        session_cookie="kosanku_session",
        max_age=8 * 60 * 60,
        same_site="lax",
        https_only=not settings.debug,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        for name, value in SECURITY_HEADERS.items():
            response.headers.setdefault(name, value)
        return response

    app.add_exception_handler(StarletteHTTPException, http_error)
    app.add_exception_handler(RequestValidationError, validation_error)
    app.add_exception_handler(Exception, server_error)
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    for module in (auth, admin, owner, tenant):
        app.include_router(module.router)

    return app


app = create_app()
