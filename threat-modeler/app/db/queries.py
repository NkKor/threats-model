"""Запросы к БД."""

from typing import List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.db_models import (
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
)


async def get_all_threats(db: AsyncSession) -> List[Threat]:
    """Получить все УБИ вместе со связями по объектам."""
    result = await db.execute(
        select(Threat).options(selectinload(Threat.pairs).joinedload(ThreatObject.object)).order_by(Threat.id)
    )
    return list(result.scalars().all())


async def get_threat_by_id(db: AsyncSession, threat_id: str) -> Optional[Threat]:
    """Получить УБИ по идентификатору."""
    result = await db.execute(
        select(Threat)
        .where(Threat.id == threat_id)
        .options(selectinload(Threat.pairs).joinedload(ThreatObject.object))
    )
    return result.scalar_one_or_none()


async def get_threats_count(db: AsyncSession) -> int:
    """Количество УБИ в БД."""
    result = await db.execute(select(func.count()).select_from(Threat))
    return int(result.scalar_one())


async def get_all_objects(db: AsyncSession) -> List[Object]:
    """Объекты воздействия."""
    result = await db.execute(select(Object).order_by(Object.num))
    return list(result.scalars().all())


async def get_all_system_types(db: AsyncSession) -> List[SystemType]:
    """Типы информационных систем."""
    result = await db.execute(select(SystemType).order_by(SystemType.code))
    return list(result.scalars().all())


async def get_all_risk_types(db: AsyncSession) -> List[RiskType]:
    """Виды риска (ущерба)."""
    result = await db.execute(select(RiskType).order_by(RiskType.code))
    return list(result.scalars().all())


async def get_all_consequences(db: AsyncSession) -> List[Consequence]:
    """Негативные последствия с применимыми типами ИС."""
    result = await db.execute(
        select(Consequence).options(selectinload(Consequence.system_types)).order_by(Consequence.code)
    )
    return list(result.scalars().all())


async def get_all_methods(db: AsyncSession) -> List[Method]:
    """Способы реализации."""
    result = await db.execute(select(Method).order_by(Method.code))
    return list(result.scalars().all())


async def get_all_impacts(db: AsyncSession) -> List[Impact]:
    """Виды воздействия."""
    result = await db.execute(select(Impact).order_by(Impact.code))
    return list(result.scalars().all())


async def get_all_violator_types(db: AsyncSession) -> List[ViolatorType]:
    """Виды нарушителей."""
    result = await db.execute(select(ViolatorType).order_by(ViolatorType.category, ViolatorType.name))
    return list(result.scalars().all())


async def get_all_violator_levels(db: AsyncSession) -> List[ViolatorLevel]:
    """Уровни возможностей нарушителей."""
    result = await db.execute(select(ViolatorLevel).order_by(ViolatorLevel.rank))
    return list(result.scalars().all())


async def get_all_techniques(db: AsyncSession) -> List[Technique]:
    """Техники реализации угроз."""
    result = await db.execute(select(Technique).order_by(Technique.code))
    return list(result.scalars().all())


async def get_all_tactics(db: AsyncSession) -> List[Tactic]:
    """Тактики с техниками."""
    result = await db.execute(
        select(Tactic).options(selectinload(Tactic.techniques)).order_by(Tactic.code)
    )
    return list(result.scalars().all())


async def get_all_interfaces(db: AsyncSession) -> List[Interface]:
    """Типы интерфейсов."""
    result = await db.execute(select(Interface).order_by(Interface.code))
    return list(result.scalars().all())
