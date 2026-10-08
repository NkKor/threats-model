"""Общие фикстуры тестов."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

PROJECT_DIR = Path(__file__).resolve().parent.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

# Тесты работают с данными относительно каталога проекта
os.chdir(PROJECT_DIR)

# Отдельная база для тестов: рабочая БД (data/threats.db) не изменяется.
# Переменные окружения задаются до импорта app.config.
TEST_DB_NAME = "test_threats.db"
TEST_DB_PATH = PROJECT_DIR / "data" / TEST_DB_NAME
os.environ["DB_PATH"] = f"./data/{TEST_DB_NAME}"
os.environ.setdefault("ENV", "testing")
os.environ.setdefault("SESSION_SECRET", "test-session-secret")


@pytest.fixture(scope="session")
def seeded_db():
    """Гарантировать, что тестовая БД создана и заполнена каноническими данными."""
    import asyncio

    from app.db.engine import engine
    from app.db.init import ensure_seeded, seed_database

    async def prepare():
        counts = await ensure_seeded()
        if not counts.get("threats"):
            counts = await seed_database(force=True)
        # Закрываем пул соединений, чтобы приложение работало в своём цикле событий
        await engine.dispose()
        return counts

    result = asyncio.run(prepare())
    yield result
    if TEST_DB_PATH.exists():
        TEST_DB_PATH.unlink()


@pytest.fixture()
def client(seeded_db):
    """Синхронный тестовый клиент FastAPI."""
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as test_client:
        yield test_client


def extract_csrf(html: str) -> str:
    """Достать CSRF-токен из HTML формы."""
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    assert match, "CSRF-токен не найден в форме"
    return match.group(1)
