"""Главный модуль приложения FastAPI."""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from app.api.endpoints.reference import router as reference_router
from app.api.endpoints.reports import router as reports_router
from app.api.endpoints.wizard import router as wizard_router
from app.config import settings
from app.db.init import ensure_seeded

BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "frontend" / "templates"
STATIC_DIR = BASE_DIR / "frontend" / "static"


@asynccontextmanager
async def lifespan(application: FastAPI):
    """Инициализация приложения: схема БД и загрузка канонических данных."""
    print(f"[START] {settings.app_name}")
    counts = await ensure_seeded()
    if counts.get("skipped"):
        print(f"[INFO] Данные уже загружены (УБИ: {counts.get('threats', 'нет данных')})")
    else:
        print(
            "[INFO] Загружены данные: "
            f"УБИ {counts.get('threats')}, связей {counts.get('threat_objects')}, "
            f"объектов {counts.get('objects')}, последствий {counts.get('consequences')}"
        )
    print(f"[INFO] Режим: {settings.env}")
    yield
    print("[STOP] Остановка приложения")


app = FastAPI(
    title=settings.app_name,
    description="Генератор моделей угроз безопасности информации (методика ФСТЭК, 2021)",
    version="0.2.0",
    lifespan=lifespan,
)

# CORS: по умолчанию пусто (same-origin). Список задаётся переменной CORS_ORIGINS.
if settings.cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
    )

# Сессия wizard: подписанная cookie, ключ берётся из настроек (SESSION_SECRET).
# max_age=None делает cookie сессионной: данные опроса исчезают при закрытии
# браузера, а также при очистке кэша или нажатии кнопки «Очистить данные».
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    session_cookie="threat_modeler_session",
    max_age=settings.session_max_age or None,
    same_site="lax",
    https_only=settings.is_production,
)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
templates.env.filters["codes_count"] = lambda value: len(value or [])
app.templates = templates

app.include_router(wizard_router)
app.include_router(reports_router)
app.include_router(reference_router)


@app.get("/")
async def root(request: Request):
    """Главная страница — шаг 1 wizard."""
    return RedirectResponse(url="/api/wizard/", status_code=303)


@app.get("/health")
async def health_check():
    """Проверка работоспособности."""
    return {"status": "healthy", "app": settings.app_name, "version": "0.2.0"}


@app.get("/api/version")
async def version():
    """Версия и основные параметры приложения."""
    return {
        "app": settings.app_name,
        "version": "0.2.0",
        "env": settings.env,
        "seed_on_startup": settings.seed_on_startup,
        "correlation": {
            "level_semantics": settings.level_semantics,
            "impacts_semantics": settings.impacts_semantics,
        },
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=settings.app_port,
        reload=not settings.is_production,
    )
