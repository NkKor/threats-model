"""API справочников.

Справочники формируются скриптом ``scripts/import_sources.py`` из источников
рабочего каталога и отдаются одним запросом — этого достаточно для проверки
данных и внешних интеграций.
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.core.reference_loader import ReferenceLoader

router = APIRouter(prefix="/api/reference", tags=["reference"])


@router.get("/")
async def get_all_references():
    """Все справочники одним ответом."""
    try:
        data = ReferenceLoader.get_all_references()
    except FileNotFoundError as error:
        raise HTTPException(status_code=500, detail=str(error))
    counts = {key: len(value) for key, value in data.items() if isinstance(value, (dict, list))}
    return {"status": "success", "data": data, "counts": counts}


@router.get("/system-types")
async def get_system_types():
    """Типы информационных систем (используются в опросе)."""
    return ReferenceLoader.get_system_types()


@router.get("/violators")
async def get_violators():
    """Виды нарушителей с уровнями возможностей.

    Для каждого вида нарушителя указан уровень Н1-Н4, для каждого уровня —
    возможность и перечень способов реализации (СП1-СП9) из файла
    «Уровни возможностей нарушителей по УБИ.xlsx».
    """
    levels = ReferenceLoader.get_violator_levels()
    return {
        "violator_types": ReferenceLoader.get_violator_types(),
        "violator_levels": {
            code: {
                "code": item.get("code"),
                "rank": item.get("rank"),
                "name": item.get("name"),
                "description": item.get("description", ""),
                "methods": item.get("methods") or [],
                "violator_types": item.get("level_violators") or [],
            }
            for code, item in levels.items()
        },
        "violator_goals_table": ReferenceLoader.get_violator_goals_table(),
    }
