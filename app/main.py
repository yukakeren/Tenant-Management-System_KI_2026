from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from .config import settings
from .db import init_db

from app.routes.tenant import router as tenant_router


BASE_DIR = Path(__file__).parent
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@asynccontextmanager
async def lifespan(_: FastAPI):
    init_db()
    settings.storage_dir.mkdir(parents=True, exist_ok=True)
    yield


def create_app() -> FastAPI:
    app = FastAPI(title="KosanKu", lifespan=lifespan, docs_url=None, redoc_url=None)
    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key.hex(),
        session_cookie="kosanku_session",
        max_age=8 * 60 * 60,
        same_site="lax",
        https_only=not settings.debug,
    )
    app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

    @app.get("/")
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html")

    # todo : app.include_router(auth.router), owner.router, tenant.router, admin.router
    app.include_router(tenant_router)

    return app


app = create_app()
