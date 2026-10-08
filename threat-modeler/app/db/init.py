"""Инициализация БД и загрузка канонических данных.

Единственный источник данных для БД — каталоги ``data/reference`` (справочники)
и ``data/seed`` (корпус УБИ), которые формирует ``scripts/import_sources.py``.
Ручные списки в коде не используются, чтобы не появлялось второе «источника истины».

Запуск::

    python -m app.db.init            # создать таблицы и загрузить данные (идемпотентно)
    python -m app.db.init --reset     # удалить БД и загрузить заново
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence

from sqlalchemy import delete, func, select

from app.config import settings
from app.core.reference_loader import ReferenceLoader
from app.db.engine import AsyncSessionLocal, engine
from app.models.db_models import (
    Base,
    Consequence,
    Impact,
    Interface,
    Method,
    Object,
    RiskType,
    SystemType,
    Tactic,
    Technique,
    Threat,
    ThreatObject,
    ViolatorLevel,
    ViolatorType,
    consequence_system_types,
    join_csv,
)

SEED_FILE = Path(settings.data_dir) / "seed" / "threats_full.json"

# Таблицы прежних версий схемы, которые нужно удалять при обновлении.
# Данные опроса и отчёты в БД не хранятся (см. app/models/db_models.py).
OBSOLETE_TABLES = ("saved_models",)


async def create_schema() -> bool:
    """Создать отсутствующие таблицы, добавить новые колонки, убрать устаревшие таблицы.

    Возвращает ``True``, если схема изменилась (нужно перезалить справочные данные).
    В БД хранятся только справочники и корпус УБИ, поэтому перезаливка безопасна.
    """
    changed = False
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        for table in OBSOLETE_TABLES:
            exists = await conn.exec_driver_sql(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table,)
            )
            if exists.first():
                await conn.exec_driver_sql(f"DROP TABLE {table}")
                changed = True
        for table in Base.metadata.sorted_tables:
            result = await conn.exec_driver_sql(f"PRAGMA table_info('{table.name}')")
            existing = {row[1] for row in result.fetchall()}
            for column in table.columns:
                if column.name in existing or column.primary_key:
                    continue
                column_type = column.type.compile(dialect=engine.dialect)
                await conn.exec_driver_sql(
                    f'ALTER TABLE "{table.name}" ADD COLUMN "{column.name}" {column_type}'
                )
                changed = True
    return changed


async def drop_schema() -> None:
    """Удалить все таблицы."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def is_empty() -> bool:
    """Проверить, что корпус УБИ не загружен."""
    async with AsyncSessionLocal() as session:
        count = await session.scalar(select(func.count()).select_from(Threat))
        return not count


async def seed_database(force: bool = False) -> Dict[str, int]:
    """Загрузить справочники и корпус УБИ в БД.

    Args:
        force: перезагрузить данные даже если УБИ уже есть.

    Returns:
        Словарь с количеством загруженных записей.
    """
    await create_schema()

    async with AsyncSessionLocal() as session:
        existing = await session.scalar(select(func.count()).select_from(Threat))
        if existing and not force:
            return {"threats": int(existing), "skipped": 1}

        if force:
            for model in (
                ThreatObject,
                Threat,
                Consequence,
                SystemType,
                RiskType,
                Interface,
                Technique,
                Tactic,
                Impact,
                Method,
                Object,
                ViolatorType,
                ViolatorLevel,
            ):
                await session.execute(delete(model))
            await session.execute(delete(consequence_system_types))
            await session.commit()

        counts = await _load_references(session)
        counts.update(await _load_corpus(session))
        await session.commit()
    return counts


async def _load_references(session) -> Dict[str, int]:
    """Загрузить справочники из data/reference."""
    counts: Dict[str, int] = {}

    objects = ReferenceLoader.get_objects()
    technologies_by_object: Dict[str, List[str]] = {}
    for tech_code, tech in ReferenceLoader.get_technologies().items():
        for obj_code in tech.get("objects") or []:
            technologies_by_object.setdefault(obj_code, []).append(tech_code)
    for code, item in objects.items():
        session.add(
            Object(
                code=code,
                num=int(item.get("num") or 0),
                name=item["name"],
                technologies=join_csv(technologies_by_object.get(code, [])),
            )
        )
    counts["objects"] = len(objects)

    methods = ReferenceLoader.get_methods()
    for code, item in methods.items():
        session.add(Method(code=code, name=item["name"]))
    counts["methods"] = len(methods)

    impacts = ReferenceLoader.get_impacts()
    for code, item in impacts.items():
        session.add(Impact(code=code, name=item["name"]))
    counts["impacts"] = len(impacts)

    system_types = ReferenceLoader.get_system_types()
    for code, item in system_types.items():
        session.add(SystemType(code=code, name=item["name"], description=item.get("description", "")))
    counts["system_types"] = len(system_types)

    risk_types = ReferenceLoader.get_risk_types()
    for code, item in risk_types.items():
        session.add(RiskType(code=code, name=item["name"]))
    counts["risk_types"] = len(risk_types)

    consequences = ReferenceLoader.get_consequences()
    for code, item in consequences.items():
        session.add(
            Consequence(
                code=code,
                risk_code=item.get("risk") or "У2",
                name=item["name"],
                conditions=item.get("conditions", ""),
            )
        )
    await session.flush()
    for code, item in consequences.items():
        for type_code in item.get("system_types") or []:
            if type_code in system_types:
                await session.execute(
                    consequence_system_types.insert().values(
                        consequence_code=code, system_type_code=type_code
                    )
                )
    counts["consequences"] = len(consequences)

    levels = ReferenceLoader.get_violator_levels()
    for code, item in levels.items():
        session.add(
            ViolatorLevel(
                code=code,
                rank=int(item.get("rank") or int(code[1])),
                name=item.get("name", ""),
                description=item.get("description", ""),
                violators=item.get("violators", ""),
                potential=item.get("potential", ""),
                methods_extended=join_csv(
                    [m["code"] for m in (item.get("methods_extended") or [])]
                ),
            )
        )
    counts["violator_levels"] = len(levels)

    violator_types = ReferenceLoader.get_violator_types()
    for code, item in violator_types.items():
        session.add(
            ViolatorType(
                code=code,
                name=item["name"],
                category=item.get("category", "external"),
                level=item.get("level", ""),
                goals=item.get("goals", ""),
            )
        )
    counts["violator_types"] = len(violator_types)

    tactics = ReferenceLoader.get_tactics()
    techniques_total = 0
    for code, item in tactics.items():
        session.add(Tactic(code=code, name=item["name"]))
        for technique_code, technique in (item.get("techniques") or {}).items():
            session.add(
                Technique(
                    code=technique_code,
                    tactic_code=code,
                    name=technique.get("name", ""),
                    description=technique.get("description", ""),
                )
            )
            techniques_total += 1
    counts["tactics"] = len(tactics)
    counts["techniques"] = techniques_total

    interfaces = ReferenceLoader.get_interfaces()
    for code, item in interfaces.items():
        session.add(
            Interface(
                code=code,
                name=item["name"],
                description=item.get("description", ""),
                methods=join_csv(item.get("methods") or []),
                source=item.get("source", ""),
            )
        )
    counts["interfaces"] = len(interfaces)
    return counts


async def _load_corpus(session) -> Dict[str, int]:
    """Загрузить корпус УБИ из data/seed."""
    if not SEED_FILE.exists():
        raise FileNotFoundError(
            f"Не найден файл корпуса {SEED_FILE}. Запустите: python -m scripts.import_sources"
        )
    with open(SEED_FILE, "r", encoding="utf-8") as handle:
        payload: Dict[str, Any] = json.load(handle)

    threats = payload.get("threats") or []
    pairs_total = 0
    for item in threats:
        session.add(
            Threat(
                id=item["id"],
                name=item["name"],
                source_note=item.get("source_note", ""),
                note=item.get("note", ""),
                violator_int=join_csv(item.get("violator_int") or []),
                violator_ext=join_csv(item.get("violator_ext") or []),
            )
        )
        for pair in item.get("pairs") or []:
            session.add(
                ThreatObject(
                    threat_id=item["id"],
                    object_code=pair["object"],
                    methods=join_csv(pair.get("methods") or []),
                    consequences=join_csv(pair.get("consequences") or []),
                    tactics=join_csv(pair.get("tactics") or []),
                    techniques=join_csv(pair.get("techniques") or []),
                )
            )
            pairs_total += 1
    return {"threats": len(threats), "threat_objects": pairs_total}


async def ensure_seeded() -> Dict[str, int]:
    """Подготовить БД при старте приложения.

    Всегда приводит схему в актуальное состояние (появление новых таблиц и
    колонок при обновлении версии), затем загружает данные, если корпус УБИ пуст
    или схема изменилась.
    """
    changed = await create_schema()

    if not settings.seed_on_startup:
        return {"skipped": 1, "reason": "seed_on_startup=false"}
    if not changed and not await is_empty():
        async with AsyncSessionLocal() as session:
            count = await session.scalar(select(func.count()).select_from(Threat))
        return {"threats": int(count), "skipped": 1}
    return await seed_database(force=True)


def reset_database_file() -> None:
    """Удалить файл SQLite (для --reset)."""
    path = Path(settings.db_path)
    if path.exists():
        path.unlink()


async def _amain(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Инициализация БД генератора моделей угроз")
    parser.add_argument("--reset", action="store_true", help="удалить БД и загрузить данные заново")
    parser.add_argument("--drop-only", action="store_true", help="только удалить таблицы")
    args = parser.parse_args(argv)

    if args.drop_only:
        await drop_schema()
        print("[OK] Таблицы удалены")
        return 0

    if args.reset:
        reset_database_file()
        print(f"[INFO] Файл БД удалён: {settings.db_path}")

    counts = await seed_database(force=True)
    print("[OK] База данных инициализирована:")
    for key, value in counts.items():
        print(f"     {key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(_amain()))
