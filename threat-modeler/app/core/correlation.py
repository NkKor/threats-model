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
import re
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from app.core.reference_loader import (
    ReferenceLoader,
    format_code_list,
    format_codes,
    get_object_name,
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
    """Строка таблицы 2 по одной УБИ.

    Объекты воздействия выводятся как «код (наименование)», а виды воздействия,
    способы реализации, негативные последствия, тактики и техники — только
    кодами через запятую: полные формулировки делали таблицу громоздкой.
    """
    data = _aggregate(threat, selected_objects)
    return ThreatView(
        ubi_id=threat.id,
        ubi_name=threat.name,
        violator_internal=", ".join(split_csv(threat.violator_int)) or EXCLUDE_MARK,
        violator_external=", ".join(split_csv(threat.violator_ext)) or EXCLUDE_MARK,
        objects=format_codes(data["objects"], get_object_name),
        methods=format_code_list(data["methods"]),
        impacts=format_code_list(threat_impacts(threat)) or EXCLUDE_MARK,
        consequences=format_code_list(data["consequences"]),
        tactics=format_code_list(data["tactics"]),
        techniques=format_code_list(data["techniques"]),
        notes=threat.note or threat.source_note or "",
    )


# --------------------------------------------------------------------------- #
# Строки итоговых таблиц 1-7
# --------------------------------------------------------------------------- #

def compute_category_levels(
    external_types: Sequence[str], internal_types: Sequence[str]
) -> Tuple[Optional[str], Optional[str]]:
    """Определить уровень возможностей категории по отмеченным нарушителям.

    Уровень не запрашивается у пользователя: он берётся автоматически как
    максимальный уровень среди выбранных видов нарушителей категории.
    """
    types = ReferenceLoader.get_violator_types()

    def best(codes: Sequence[str]) -> Optional[str]:
        best_rank = 0
        best_code: Optional[str] = None
        for code in codes:
            level = (types.get(code) or {}).get("level")
            rank = level_rank(level)
            if rank is not None and rank > best_rank:
                best_rank = rank
                best_code = level
        return best_code

    return best(external_types or []), best(internal_types or [])


def actual_violator_codes(profile: UserProfile) -> List[str]:
    """Коды отмеченных видов нарушителей (внешние + внутренние, без повторов)."""
    result: List[str] = []
    for code in list(profile.violators.external_types) + list(profile.violators.internal_types):
        if code and code not in result:
            result.append(code)
    return result


def _norm_text(text: str) -> str:
    text = (text or "").lower().replace("ё", "е")
    text = re.sub(r"[«»\"'(),.;:–—-]", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def _match_goal_violators(text: str, types: Dict[str, Dict[str, object]]) -> List[str]:
    """Сопоставить наименование строки таблицы целей с видами нарушителей."""
    norm = _norm_text(text)
    matched: List[str] = []
    for code, item in types.items():
        key = _norm_text(str(item.get("name", "")))
        if not key:
            continue
        if key in norm or norm in key:
            matched.append(code)
            continue
        tokens = [token for token in key.split() if len(token) > 4]
        hits = sum(1 for token in tokens if token in norm)
        if tokens and hits >= max(2, (len(tokens) + 1) // 2):
            matched.append(code)
    return matched


def build_table1_rows(risk_table: Sequence[ConsequenceView]) -> List[Dict[str, str]]:
    """Таблица 1: виды риска (ущерба) и применимые негативные последствия."""
    rows: List[Dict[str, str]] = []
    for index, item in enumerate(risk_table, start=1):
        risk_title = f"{item.risk}. {item.risk_name}".strip(". ") if item.risk_name else item.risk
        rows.append(
            {
                "row_number": str(index),
                "code": item.code,
                "risk": item.risk,
                "risk_name": item.risk_name,
                "risk_title": risk_title,
                "name": item.name,
                "conditions": item.conditions,
            }
        )
    return rows


def build_table2_rows(
    risk_table: Sequence[ConsequenceView], selected_objects: Sequence[str]
) -> List[Dict[str, str]]:
    """Таблица 2: для применимых последствий — выбранные объекты и виды воздействия.

    Берётся связь «негативное последствие -> объекты воздействия -> виды
    воздействия» из таблицы 3 Методики. В колонке объектов остаются только
    объекты, выбранные пользователем на шаге 4.
    """
    mapping = ReferenceLoader.get_consequence_impact_mapping()
    allowed = set(selected_objects or [])
    rows: List[Dict[str, str]] = []
    for item in risk_table:
        info = mapping.get(item.code)
        if not info:
            continue
        objects = [code for code in (info.get("objects") or []) if code in allowed]
        impacts = list(info.get("impacts") or [])
        rows.append(
            {
                "consequence": item.name,
                "objects": format_codes(objects, get_object_name) or EXCLUDE_MARK,
                "impacts": format_code_list(impacts) or EXCLUDE_MARK,
            }
        )
    return rows


def build_table3_rows() -> List[Dict[str, str]]:
    """Таблица 3: характеристика видов нарушителей (все 13 позиций)."""
    rows: List[Dict[str, str]] = []
    for index, item in enumerate(ReferenceLoader.get_violator_types().values(), start=1):
        category = "Внутренний" if item.get("category") == "internal" else "Внешний"
        rows.append(
            {
                "row_number": str(index),
                "violator": str(item.get("name", "")),
                "category": category,
                "goals": str(item.get("goals") or EXCLUDE_MARK),
            }
        )
    return rows


def build_table4_rows(actual_codes: Sequence[str]) -> List[Dict[str, str]]:
    """Таблица 4: уровни возможностей нарушителей Н1-Н4 и их носители."""
    levels = ReferenceLoader.get_violator_levels()
    types = ReferenceLoader.get_violator_types()
    rows: List[Dict[str, str]] = []
    for index, (code, item) in enumerate(levels.items(), start=1):
        names = [
            str(types[code_of_type].get("name", ""))
            for code_of_type in actual_codes
            if types.get(code_of_type, {}).get("level") == code
        ]
        rows.append(
            {
                "row_number": str(index),
                "level": f"{code}. {item.get('name', '')}".strip(),
                "level_name": item.get("name", ""),
                "capabilities": item.get("description", ""),
                "violators": "; ".join(names) or EXCLUDE_MARK,
            }
        )
    return rows


def build_table5_rows(
    actual_codes: Sequence[str], goals_table: Sequence[Dict[str, object]]
) -> List[Dict[str, str]]:
    """Таблица 5: цели актуальных нарушителей по видам ущерба.

    Из таблицы целей «Виды нарушителей.docx» остаются строки, относящиеся к
    выбранным (актуальным) видам нарушителей. Для составных строк «Сговор ...»
    требуется, чтобы актуальными были оба участника.
    """
    types = ReferenceLoader.get_violator_types()
    actual = set(actual_codes)
    rows: List[Dict[str, str]] = []
    for item in goals_table:
        violator = str(item.get("violator", ""))
        matched = _match_goal_violators(violator, types)
        hits = [code for code in matched if code in actual]
        is_sgovor = _norm_text(violator).startswith("сговор")
        if is_sgovor:
            if len(hits) < 2:
                continue
        elif not hits:
            continue
        rows.append(
            {
                "violator": violator,
                "damage_physical": str(item.get("damage_physical") or EXCLUDE_MARK),
                "damage_legal": str(item.get("damage_legal") or EXCLUDE_MARK),
                "damage_state": str(item.get("damage_state") or EXCLUDE_MARK),
                "correspondence": str(item.get("correspondence") or EXCLUDE_MARK),
            }
        )
    return rows


def build_table6_rows(
    actual_codes: Sequence[str],
    profile: UserProfile,
    threats: Sequence[Threat],
) -> List[Dict[str, str]]:
    """Таблица 6: актуальные способы реализации по паре «нарушитель x объект».

    Способы строки — пересечение способов, доступных виду нарушителя по его
    уровню (``Уровни возможностей нарушителей по УБИ.xlsx``), и способов,
    встречающихся у выбранного объекта в отобранных УБИ. Доступные интерфейсы —
    выбранные типы интерфейсов, через которые доступен хотя бы один из этих
    способов. Пустые строки не выводятся.
    """
    types = ReferenceLoader.get_violator_types()
    interfaces = ReferenceLoader.get_interfaces()
    object_methods: Dict[str, Set[str]] = {}
    for threat in threats:
        for pair in matched_pairs(threat, profile.selected_objects) or list(threat.pairs):
            object_methods.setdefault(pair.object_code, set()).update(pair.method_codes)

    rows: List[Dict[str, str]] = []
    for code in actual_codes:
        item = types.get(code) or {}
        violator_methods = set(item.get("methods") or [])
        category = "Внутренний" if item.get("category") == "internal" else "Внешний"
        for object_code in profile.selected_objects:
            methods = violator_methods & object_methods.get(object_code, set())
            if not methods:
                continue
            interface_names = [
                str(interfaces[code_iface].get("name", code_iface))
                for code_iface in profile.interfaces
                if set((interfaces.get(code_iface) or {}).get("methods") or []) & methods
            ]
            rows.append(
                {
                    "row_number": str(len(rows) + 1),
                    "violator": str(item.get("name", code)),
                    "category": category,
                    "objects": format_codes([object_code], get_object_name),
                    "interfaces": ", ".join(interface_names) or EXCLUDE_MARK,
                    "methods": format_code_list(list(methods)) or EXCLUDE_MARK,
                }
            )
    return rows


def build_table7_rows(
    corpus: Sequence[Threat],
    filtered_ids: Set[str],
    selected_objects: Sequence[str],
) -> List[Dict[str, str]]:
    """Таблица 7: все УБИ корпуса; данные — только по отобранным.

    Строка каждой УБИ присутствует всегда, но заполняется только если угроза
    прошла отбор по профилю системы; остальные колонки остаются пустыми.
    """
    empty = {
        "ubi_name": "",
        "violator_internal": "",
        "violator_external": "",
        "objects": "",
        "methods": "",
        "impacts": "",
        "consequences": "",
        "tactics": "",
        "techniques": "",
        "notes": "",
    }
    rows: List[Dict[str, str]] = []
    for threat in corpus:
        row: Dict[str, str] = {"ubi_id": threat.id, **empty}
        if threat.id in filtered_ids:
            view = build_threat_view(threat, selected_objects)
            row.update(
                {
                    "ubi_name": view.ubi_name,
                    "violator_internal": view.violator_internal,
                    "violator_external": view.violator_external,
                    "objects": view.objects,
                    "methods": view.methods,
                    "impacts": view.impacts,
                    "consequences": view.consequences,
                    "tactics": view.tactics,
                    "techniques": view.techniques,
                    "notes": view.notes,
                }
            )
        rows.append(row)
    return rows


def build_report(
    profile: UserProfile,
    threats: Sequence[Threat],
    corpus_size: int,
    corpus: Optional[Sequence[Threat]] = None,
) -> ReportPreview:
    """Собрать предпросмотр отчёта (7 итоговых таблиц и сводка)."""
    selected_impacts = list(getattr(profile, "selected_impacts", []) or [])
    risk_table = build_risk_table(profile.system.system_types)
    rows = [build_threat_view(threat, profile.selected_objects) for threat in threats]
    full_corpus = list(corpus if corpus is not None else threats)
    actual_codes = actual_violator_codes(profile)
    goals_table = ReferenceLoader.get_violator_goals_table()

    table_rows = {
        "table1": build_table1_rows(risk_table),
        "table2": build_table2_rows(risk_table, profile.selected_objects),
        "table3": build_table3_rows(),
        "table4": build_table4_rows(actual_codes),
        "table5": build_table5_rows(actual_codes, goals_table),
        "table6": build_table6_rows(actual_codes, profile, threats),
        "table7": build_table7_rows(full_corpus, {threat.id for threat in threats}, profile.selected_objects),
    }

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
        table_rows=table_rows,
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

    def build_report(self, profile: UserProfile, threats: Sequence[Threat], corpus_size: int, corpus: Optional[Sequence[Threat]] = None) -> ReportPreview:
        """Собрать предпросмотр отчёта."""
        return build_report(profile, threats, corpus_size, corpus=corpus)
