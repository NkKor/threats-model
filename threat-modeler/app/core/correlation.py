"""Движок корреляции: отбор УБИ по профилю системы.

Модель корреляции — ``бдму.xlsx`` (эталон заказчика): каждая УБИ связана с
объектами воздействия, и для каждой пары «УБИ x объект» заданы способы
реализации, негативные последствия, тактики и техники. Дополнительно:

* уровни возможностей нарушителей по каждой УБИ — ``сводная таблица.docx``;
* применимость негативных последствий по типам ИС — ``ИС и негативные
  последствия.xlsx``;
* связь «тип интерфейса -> способы реализации» — ``interfaces.yaml``,
  выведена из «Способы реализации угроз безопасности информации.docx».

Правила отбора (пустой выбор по измерению = измерение не ограничивает):

R1. Объекты: УБИ проходит, если хотя бы одна её пара ссылается на выбранный объект.
R2. Последствия: УБИ проходит, если хотя бы одно её последствие применимо к
    выбранным типам ИС.
R3. Нарушители: для каждой заявленной категории (внутренние/внешние) с уровнем
    возможностей L УБИ проходит, если указанный для неё уровень Li удовлетворяет
    ``rank(Li) <= rank(L)`` — нарушитель с более высокими возможностями может
    реализовать всё, что доступно более слабому. УБИ остаётся в перечне, если она
    реализуема хотя бы одной заявленной категорией нарушителей.
R4. Интерфейсы: УБИ проходит, если хотя бы один способ реализации её пар доступен
    через выбранные типы интерфейсов.
R5. Виды воздействия: УБИ проходит, если хотя бы один выведенный для неё вид
    воздействия выбран. Если виды воздействия для УБИ не определены (соответствия
    в таблице 3 Методики нет), ограничение к ней не применяется.
"""

from __future__ import annotations

import logging
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from app.core.reference_loader import (
    ReferenceLoader,
    format_codes,
    get_consequence_name,
    get_impact_name,
    get_method_name,
    get_object_name,
    get_tactic_name,
    get_technique_name,
)
from app.config import settings
from app.models.db_models import Threat, ThreatObject, split_csv
from app.models.schemas import (
    ConsequenceView,
    ReportPreview,
    ThreatView,
    UserProfile,
)

logger = logging.getLogger(__name__)

EXCLUDE_MARK = "―"


# --------------------------------------------------------------------------- #
# Справочные выборки (с кэшем на уровне ReferenceLoader)
# --------------------------------------------------------------------------- #

def level_rank(level: Optional[str]) -> Optional[int]:
    """Числовой ранг уровня возможностей (Н1 -> 1 ... Н4 -> 4)."""
    if not level:
        return None
    item = ReferenceLoader.get_violator_levels().get(level)
    if item and item.get("rank"):
        return int(item["rank"])
    if len(level) == 2 and level[0] == "Н" and level[1] in "1234":
        return int(level[1])
    return None


def level_passes(profile_level: Optional[str], threat_levels: Sequence[str]) -> bool:
    """Может ли нарушитель уровня ``profile_level`` реализовать угрозу.

    Режим задаётся настройкой ``LEVEL_SEMANTICS``:

    * ``capability`` (по умолчанию) — нарушитель реализует угрозы своего уровня и
      ниже: достаточно, чтобы у угрозы был указан уровень не выше профиля;
    * ``strict`` — уровень нарушителя должен быть явно указан у угрозы.

    Пустой список уровней угрозы означает «не ограничено» (в сводной таблице
    стоит «―»), такие УБИ не отбрасываются по данному измерению.
    """
    profile = level_rank(profile_level)
    if profile is None:
        return True
    if not threat_levels:
        return True
    if settings.level_semantics == "strict":
        return profile_level in threat_levels
    for level in threat_levels:
        rank = level_rank(level)
        if rank is not None and rank <= profile:
            return True
    return False


def violator_check(
    external_level: Optional[str],
    internal_level: Optional[str],
    threat: Threat,
) -> bool:
    """Проверка R3 по обеим категориям нарушителей."""
    checks: List[bool] = []
    if external_level:
        checks.append(level_passes(external_level, split_csv(threat.violator_ext)))
    if internal_level:
        checks.append(level_passes(internal_level, split_csv(threat.violator_int)))
    if not checks:
        return True
    return any(checks)


# --------------------------------------------------------------------------- #
# Фильтрация
# --------------------------------------------------------------------------- #

def check_objects(selected_objects: Sequence[str], threat: Threat) -> bool:
    """R1: пересечение объектов угрозы с выбранными."""
    if not selected_objects:
        return True
    selected = set(selected_objects)
    return any(pair.object_code in selected for pair in threat.pairs)


def check_consequences(applicable: Set[str], threat: Threat) -> bool:
    """R2: хотя бы одно последствие угрозы применимо к выбранным типам ИС."""
    if not applicable:
        return True
    for pair in threat.pairs:
        if applicable & set(pair.consequence_codes):
            return True
    return False


def check_interfaces(available_methods: Set[str], threat: Threat) -> bool:
    """R4: хотя бы один способ реализации доступен через выбранные интерфейсы."""
    if not available_methods:
        return True
    for pair in threat.pairs:
        if available_methods & set(pair.method_codes):
            return True
    return False


def threat_impacts(threat: Threat) -> List[str]:
    """Виды воздействия, выведенные для УБИ через таблицу 3 Методики."""
    codes = {code for pair in threat.pairs for code in pair.consequence_codes}
    return ReferenceLoader.impacts_for_consequences(list(codes))


def check_impacts(selected_impacts: Sequence[str], threat: Threat) -> bool:
    """R5: пересечение выбранных видов воздействия с выведенными для УБИ.

    Поведение для УБИ, у которых виды воздействия определить не удалось (нет
    соответствия в таблице 3), задаётся настройкой ``IMPACTS_SEMANTICS``:

    * ``keep`` (по умолчанию) — ограничение не применяется: иначе УБИ терялась бы
      из-за неполноты справочника, а не из-за свойств системы;
    * ``exclude`` — УБИ исключается.
    """
    if not selected_impacts:
        return True
    derived = set(threat_impacts(threat))
    if not derived:
        return settings.impacts_semantics != "exclude"
    return bool(derived & set(selected_impacts))


def matched_pairs(threat: Threat, selected_objects: Sequence[str]) -> List[ThreatObject]:
    """Пары угрозы, попавшие в выбор по объектам (или все, если объекты не выбраны)."""
    if not selected_objects:
        return list(threat.pairs)
    selected = set(selected_objects)
    return [pair for pair in threat.pairs if pair.object_code in selected]


def filter_threats(
    threats: Iterable[Threat],
    profile: UserProfile,
    applicable_consequences: Optional[Set[str]] = None,
    available_methods: Optional[Set[str]] = None,
) -> List[Threat]:
    """Отобрать УБИ, соответствующие профилю системы."""
    if applicable_consequences is None:
        applicable_consequences = set(
            ReferenceLoader.consequences_for_system_types(profile.system.system_types)
        )
    if available_methods is None:
        available_methods = set(ReferenceLoader.methods_for_interfaces(profile.interfaces))

    selected_objects = list(profile.selected_objects)
    selected_impacts = list(getattr(profile, "selected_impacts", []) or [])
    external_level = profile.violators.external_level
    internal_level = profile.violators.internal_level

    result: List[Threat] = []
    for threat in threats:
        if not check_objects(selected_objects, threat):
            continue
        if not check_consequences(applicable_consequences, threat):
            continue
        if not check_impacts(selected_impacts, threat):
            continue
        if not violator_check(external_level, internal_level, threat):
            continue
        if not check_interfaces(available_methods, threat):
            continue
        result.append(threat)
    return result


# --------------------------------------------------------------------------- #
# Отчёт
# --------------------------------------------------------------------------- #

def _aggregate(threat: Threat, selected_objects: Sequence[str]) -> Dict[str, List[str]]:
    """Объединить корреляцию по парам угрозы, попавшим в выбор."""
    pairs = matched_pairs(threat, selected_objects) or list(threat.pairs)
    aggregated: Dict[str, List[str]] = {
        "objects": [],
        "methods": [],
        "consequences": [],
        "tactics": [],
        "techniques": [],
    }
    for pair in pairs:
        for key, values in (
            ("objects", [pair.object_code]),
            ("methods", pair.method_codes),
            ("consequences", pair.consequence_codes),
            ("tactics", pair.tactic_codes),
            ("techniques", pair.technique_codes),
        ):
            for value in values:
                if value not in aggregated[key]:
                    aggregated[key].append(value)
    return aggregated


def build_risk_table(system_types: Sequence[str]) -> List[ConsequenceView]:
    """Таблица 1: виды риска и применимые негативные последствия."""
    risk_types = ReferenceLoader.get_risk_types()
    rows: List[ConsequenceView] = []
    for code, item in ReferenceLoader.get_consequences().items():
        if system_types and not (set(system_types) & set(item.get("system_types") or [])):
            continue
        risk = item.get("risk", "")
        rows.append(
            ConsequenceView(
                code=code,
                risk=risk,
                risk_name=risk_types.get(risk, {}).get("name", ""),
                name=item.get("name", ""),
                conditions=item.get("conditions", ""),
            )
        )
    rows.sort(key=lambda row: (row.risk, int(row.code.split(".")[1])))
    return rows


def build_threat_view(threat: Threat, selected_objects: Sequence[str]) -> ThreatView:
    """Строка таблицы 2 по одной УБИ."""
    data = _aggregate(threat, selected_objects)
    return ThreatView(
        ubi_id=threat.id,
        ubi_name=threat.name,
        violator_internal=", ".join(split_csv(threat.violator_int)) or EXCLUDE_MARK,
        violator_external=", ".join(split_csv(threat.violator_ext)) or EXCLUDE_MARK,
        objects=format_codes(data["objects"], get_object_name),
        methods=format_codes(data["methods"], get_method_name),
        impacts=format_codes(threat_impacts(threat), get_impact_name) or EXCLUDE_MARK,
        consequences=format_codes(data["consequences"], get_consequence_name),
        tactics=format_codes(data["tactics"], get_tactic_name),
        techniques=format_codes(data["techniques"], get_technique_name),
        notes=threat.note or threat.source_note or "",
    )


def build_report(profile: UserProfile, threats: Sequence[Threat], corpus_size: int) -> ReportPreview:
    """Собрать предпросмотр отчёта (таблица 1 + таблица 2 + сводка)."""
    selected_impacts = list(getattr(profile, "selected_impacts", []) or [])
    risk_table = build_risk_table(profile.system.system_types)
    rows = [build_threat_view(threat, profile.selected_objects) for threat in threats]

    by_object: Dict[str, int] = {}
    for threat in threats:
        for pair in matched_pairs(threat, profile.selected_objects) or list(threat.pairs):
            by_object[pair.object_code] = by_object.get(pair.object_code, 0) + 1
    by_risk: Dict[str, int] = {}
    for row in risk_table:
        by_risk[row.risk] = by_risk.get(row.risk, 0) + 1

    impacts_counter: Dict[str, int] = {}
    for threat in threats:
        for impact in threat_impacts(threat):
            impacts_counter[impact] = impacts_counter.get(impact, 0) + 1

    statistics = {
        "selected_objects": len(profile.selected_objects),
        "selected_interfaces": len(profile.interfaces),
        "selected_system_types": len(profile.system.system_types),
        "selected_impacts": len(selected_impacts),
        "applicable_consequences": len(risk_table),
        "threats_by_object": by_object,
        "consequences_by_risk": by_risk,
        "threats_by_impact": impacts_counter,
        "selected_objects_names": [
            f"{code} ({get_object_name(code)})" for code in profile.selected_objects
        ],
        "selected_system_type_names": [
            ReferenceLoader.get_system_types().get(code, {}).get("name", code)
            for code in profile.system.system_types
        ],
    }
    return ReportPreview(
        profile=profile,
        risk_table=risk_table,
        threats=rows,
        total_threats=len(rows),
        total_corpus=corpus_size,
        statistics=statistics,
    )


# --------------------------------------------------------------------------- #
# Совместимость с прежним API
# --------------------------------------------------------------------------- #

class CorrelationEngine:
    """Обёртка над функциями корреляции (сохранена для совместимости)."""

    def correlate(self, threats: Iterable[Threat], profile: UserProfile) -> List[Threat]:
        """Отобрать УБИ по профилю."""
        return filter_threats(threats, profile)

    def build_report(self, profile: UserProfile, threats: Sequence[Threat], corpus_size: int) -> ReportPreview:
        """Собрать предпросмотр отчёта."""
        return build_report(profile, threats, corpus_size)
