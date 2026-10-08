"""Тесты движка корреляции (правила R1-R4)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.core.correlation import (
    build_report,
    build_threat_view,
    check_consequences,
    check_impacts,
    check_interfaces,
    check_objects,
    filter_threats,
    level_passes,
    level_rank,
    threat_impacts,
    violator_check,
)
from app.core.reference_loader import ReferenceLoader
from app.models.schemas import SystemProfile, UserProfile, ViolatorProfile


def make_pair(object_code="О4", methods=("СП1",), consequences=("у2.26",), tactics=("Т2",), techniques=("Т2.5",)):
    """Создать объект-заглушку пары «УБИ x объект»."""
    return SimpleNamespace(
        object_code=object_code,
        method_codes=list(methods),
        consequence_codes=list(consequences),
        tactic_codes=list(tactics),
        technique_codes=list(techniques),
    )


def make_threat(threat_id="УБИ.001", int_levels=(), ext_levels=(), pairs=()):
    """Создать объект-заглушку УБИ."""
    return SimpleNamespace(
        id=threat_id,
        name=f"Угроза {threat_id}",
        note="",
        source_note="",
        violator_int=",".join(int_levels),
        violator_ext=",".join(ext_levels),
        pairs=list(pairs),
    )


# --------------------------------------------------------------------------- #
# Уровни возможностей нарушителей
# --------------------------------------------------------------------------- #

def test_level_rank():
    """Ранги уровней: Н1 -> 1 ... Н4 -> 4 (Н4 — высокие возможности)."""
    assert level_rank("Н1") == 1
    assert level_rank("Н4") == 4
    assert level_rank(None) is None
    assert level_rank("Н9") is None


@pytest.mark.parametrize(
    "profile_level, threat_levels, expected",
    [
        ("Н4", ["Н1"], True),    # высокие возможности покрывают базовые
        ("Н2", ["Н1"], True),
        ("Н2", ["Н2", "Н3"], True),
        ("Н4", ["Н2", "Н3"], True),
        ("Н1", ["Н2", "Н3"], False),  # базовые возможности не покрывают повышенные
        ("Н1", ["Н4"], False),
        ("Н4", [], True),        # «―» в источнике не ограничивает
        (None, ["Н4"], True),    # уровень не указан — фильтр не применяется
    ],
)
def test_level_passes(profile_level, threat_levels, expected):
    """Правило R3: нарушитель реализует угрозы своего уровня и ниже."""
    assert level_passes(profile_level, threat_levels) is expected


def test_violator_check_uses_any_category():
    """УБИ проходит, если реализуема хотя бы одной заявленной категорией нарушителей."""
    threat = make_threat(ext_levels=["Н2", "Н3"], int_levels=[])
    # Внешний уровень указан, внутренний — нет: проверяется только внешний
    assert violator_check("Н3", None, threat) is True
    assert violator_check("Н1", None, threat) is False
    # Внутренние нарушители не заявлены уровнями — фильтр не применяется
    assert violator_check(None, "Н1", threat) is True


# --------------------------------------------------------------------------- #
# Правила R1, R2, R4
# --------------------------------------------------------------------------- #

def test_check_objects():
    """R1: пересечение выбранных объектов с объектами угрозы."""
    threat = make_threat(pairs=[make_pair("О4"), make_pair("О31")])
    assert check_objects(["О4", "О5"], threat) is True
    assert check_objects(["О1"], threat) is False
    assert check_objects([], threat) is True


def test_check_consequences():
    """R2: применимость последствий к типам ИС."""
    threat = make_threat(pairs=[make_pair(consequences=("у2.26",))])
    assert check_consequences({"у2.26"}, threat) is True
    assert check_consequences({"у3.27"}, threat) is False
    assert check_consequences(set(), threat) is True


def test_check_interfaces():
    """R4: доступность способов реализации через выбранные интерфейсы."""
    threat = make_threat(pairs=[make_pair(methods=("СП1", "СП5"))])
    assert check_interfaces({"СП1"}, threat) is True
    assert check_interfaces({"СП7"}, threat) is False
    assert check_interfaces(set(), threat) is True


def test_threat_impacts_derived_from_consequence_table():
    """Виды воздействия выводятся через таблицу 3 Методики."""
    # у2.26 (утечка конфиденциальной информации) соответствует П17 -> В1, В2, В7
    threat = make_threat(pairs=[make_pair(consequences=("у2.26",))])
    assert threat_impacts(threat) == ["В1", "В2", "В7"]

    # у1.9 не имеет соответствия в таблице 3
    unmapped = make_threat(pairs=[make_pair(consequences=("у1.9",))])
    assert threat_impacts(unmapped) == []


def test_check_impacts_rule():
    """R5: фильтр по видам воздействия и его поведение при неполных данных."""
    threat = make_threat(pairs=[make_pair(consequences=("у2.26",))])
    assert check_impacts(["В1"], threat) is True
    assert check_impacts(["В4"], threat) is False
    assert check_impacts([], threat) is True

    # Последствие без соответствия в таблице 3 не отбрасывает УБИ
    unmapped = make_threat(pairs=[make_pair(consequences=("у1.9",))])
    assert check_impacts(["В4"], unmapped) is True


def test_consequence_impact_alignment_is_consistent():
    """Выравнивание таблицы 3: 17 соответствий, порядок сохранён, коды валидны."""
    mapping = ReferenceLoader.get_consequence_impact_mapping()
    impacts = set(ReferenceLoader.get_impacts())
    consequences = set(ReferenceLoader.get_consequences())

    assert len(mapping) == 17, "ожидается 17 сопоставленных последствий таблицы 3"
    numbers = []
    for code, item in mapping.items():
        assert code in consequences, f"{code} отсутствует в справочнике последствий"
        assert item["impacts"], f"{code} без видов воздействия"
        assert set(item["impacts"]) <= impacts
        assert item["match"] >= 0.6, f"низкая схожесть сопоставления {code}: {item['match']}"
        numbers.append(int(code.split(".")[1]))

    assert numbers == sorted(numbers), "нарушен порядок сопоставления последствий"
    assert 0.6 <= min(item["match"] for item in mapping.values())


def test_every_reference_impact_has_mapping():
    """Все виды воздействия В1-В7 задействованы в соответствиях."""
    used = set()
    for codes in ReferenceLoader.get_consequence_impacts().values():
        used.update(codes)
    assert used == set(ReferenceLoader.get_impacts())


def test_reference_interface_methods_are_derived_from_methodology():
    """Справочник интерфейсов содержит только известные коды СП."""
    methods = set(ReferenceLoader.get_methods())
    interfaces = ReferenceLoader.get_interfaces()
    assert interfaces, "справочник интерфейсов пуст"
    for code, item in interfaces.items():
        assert item["methods"], f"интерфейс {code} без способов реализации"
        assert set(item["methods"]) <= methods


# --------------------------------------------------------------------------- #
# Полный цикл фильтрации и отчёт
# --------------------------------------------------------------------------- #

def test_level_semantics_modes_are_switchable():
    """Трактовка уровней нарушителей переключается настройкой LEVEL_SEMANTICS."""
    from app.config import settings

    threat_levels = ["Н2", "Н3"]
    original = settings.level_semantics
    try:
        settings.level_semantics = "capability"
        assert level_passes("Н4", threat_levels) is True   # покрывает Н2 и Н3
        assert level_passes("Н1", threat_levels) is False

        settings.level_semantics = "strict"
        assert level_passes("Н4", threat_levels) is False  # Н4 в списке отсутствует
        assert level_passes("Н3", threat_levels) is True
    finally:
        settings.level_semantics = original


def test_impacts_semantics_modes_are_switchable():
    """Поведение при неопределённых видах воздействия переключается настройкой."""
    from app.config import settings

    unmapped = make_threat(pairs=[make_pair(consequences=("у1.9",))])
    original = settings.impacts_semantics
    try:
        settings.impacts_semantics = "keep"
        assert check_impacts(["В4"], unmapped) is True
        settings.impacts_semantics = "exclude"
        assert check_impacts(["В4"], unmapped) is False
    finally:
        settings.impacts_semantics = original


def test_filter_threats_end_to_end():
    """Сквозная проверка: все четыре правила применяются согласованно."""
    threats = [
        make_threat("УБИ.100", ext_levels=["Н1"], pairs=[make_pair("О4", ("СП1",), ("у2.26",))]),
        make_threat("УБИ.101", ext_levels=["Н4"], pairs=[make_pair("О4", ("СП1",), ("у2.26",))]),
        make_threat("УБИ.102", ext_levels=["Н1"], pairs=[make_pair("О1", ("СП1",), ("у2.26",))]),
        make_threat("УБИ.103", ext_levels=["Н1"], pairs=[make_pair("О4", ("СП7",), ("у2.26",))]),
        make_threat("УБИ.104", ext_levels=["Н1"], pairs=[make_pair("О4", ("СП1",), ("у3.27",))]),
    ]
    profile = UserProfile(
        system=SystemProfile(system_types=["ПДн"]),
        violators=ViolatorProfile(external_level="Н2"),
        interfaces=["user"],
        selected_objects=["О4"],
    )
    result = filter_threats(threats, profile, applicable_consequences={"у2.26"}, available_methods={"СП1"})
    assert [threat.id for threat in result] == ["УБИ.100"]


def test_build_report_structure():
    """Отчёт содержит таблицу 1 и таблицу 2 с заполненными полями."""
    threat = make_threat("УБИ.100", int_levels=["Н2"], ext_levels=["Н2", "Н3"], pairs=[make_pair()])
    profile = UserProfile(
        system=SystemProfile(system_types=["ПДн"]),
        violators=ViolatorProfile(external_level="Н3"),
        interfaces=["user"],
        selected_objects=["О4"],
    )
    report = build_report(profile, [threat], corpus_size=227)

    assert report.total_threats == 1
    assert report.total_corpus == 227
    assert report.risk_table, "таблица 1 не сформирована"
    assert all(item.risk in {"У1", "У2", "У3"} for item in report.risk_table)

    row = report.threats[0]
    assert row.ubi_id == "УБИ.100"
    assert "О4" in row.objects
    assert "СП1" in row.methods
    assert "у2.26" in row.consequences
    assert row.violator_internal == "Н2"
    assert row.violator_external == "Н2, Н3"


def test_threat_view_excludes_marker_for_empty_levels():
    """Отсутствие уровня нарушителя отображается прочерком."""
    threat = make_threat("УБИ.200", int_levels=[], ext_levels=["Н1"], pairs=[make_pair()])
    row = build_threat_view(threat, ["О4"])
    assert row.violator_internal == "―"
    assert row.violator_external == "Н1"
