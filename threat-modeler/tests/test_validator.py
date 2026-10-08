"""Тесты валидации шагов wizard."""

from __future__ import annotations

from app.core.reference_loader import ReferenceLoader
from app.core.validator import (
    WizardValidator,
    validate_interfaces,
    validate_objects,
    validate_system_profile,
    validate_violator_profile,
)


def first_system_type() -> str:
    return next(iter(ReferenceLoader.get_system_types()))


def external_violator() -> str:
    types = ReferenceLoader.get_violator_types()
    return next(code for code, item in types.items() if item["category"] == "external")


def internal_violator() -> str:
    types = ReferenceLoader.get_violator_types()
    return next(code for code, item in types.items() if item["category"] == "internal")


def test_system_profile_requires_system_type():
    """Без типа ИС отчёт по последствиям не построить."""
    result = validate_system_profile({"system_types": [], "technologies": []})
    assert not result.is_valid
    assert any("тип информационной системы" in error.lower() for error in result.errors)


def test_system_profile_accepts_valid_data():
    """Корректный профиль системы проходит проверку."""
    result = validate_system_profile(
        {
            "system_types": [first_system_type()],
            "technologies": list(ReferenceLoader.get_technologies())[:2],
            "processes_pd": False,
        }
    )
    assert result.is_valid, result.errors


def test_system_profile_requires_pd_level():
    """При обработке ПДн уровень защищённости обязателен."""
    result = validate_system_profile(
        {"system_types": [first_system_type()], "processes_pd": True, "pd_security_level": None}
    )
    assert not result.is_valid
    assert any("ПДн" in error for error in result.errors)


def test_system_profile_rejects_unknown_system_type():
    """Неизвестный тип ИС отклоняется."""
    result = validate_system_profile({"system_types": ["НетТакогоТипа"]})
    assert not result.is_valid


def test_violator_category_is_checked():
    """Нарушитель должен попадать в заявленную категорию."""
    result = validate_violator_profile({"external_types": [internal_violator()]})
    assert not result.is_valid
    assert any("категории" in error or "относится" in error for error in result.errors)


def test_violator_level_is_checked():
    """Несуществующий уровень возможностей отклоняется."""
    result = validate_violator_profile({"external_types": [external_violator()], "external_level": "Н9"})
    assert not result.is_valid


def test_violator_warns_when_types_without_level():
    """Отсутствие уровня при выбранных нарушителях даёт предупреждение, а не ошибку."""
    result = validate_violator_profile({"external_types": [external_violator()], "external_level": None})
    assert result.is_valid
    assert result.warnings


def test_interfaces_and_objects_validation():
    """Проверка шагов 3 и 4."""
    known_interface = next(iter(ReferenceLoader.get_interfaces()))
    assert validate_interfaces([known_interface]).is_valid
    assert not validate_interfaces(["unknown_interface"]).is_valid

    known_object = next(iter(ReferenceLoader.get_objects()))
    assert validate_objects([known_object]).is_valid
    assert not validate_objects([]).is_valid
    assert not validate_objects(["О999"]).is_valid


def test_wizard_validator_dispatch():
    """Диспетчер валидатора возвращает результат по номеру шага."""
    validator = WizardValidator()
    assert validator.validate_step(1, {"system_types": [first_system_type()]}).is_valid
    assert not validator.validate_step(3, {"interfaces": ["nope"]}).is_valid
    assert not validator.validate_step(9, {}).is_valid
