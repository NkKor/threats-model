"""Валидация данных wizard."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.core.reference_loader import ReferenceLoader
from app.models.schemas import UserProfile

VALID_PD_LEVELS = {1, 2, 3, 4}


class ValidationResult:
    """Результат проверки шага: ошибки и предупреждения."""

    def __init__(self, errors: List[str] | None = None, warnings: List[str] | None = None) -> None:
        self.errors: List[str] = errors or []
        self.warnings: List[str] = warnings or []

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def as_tuple(self) -> Tuple[bool, List[str], List[str]]:
        return self.is_valid, self.errors, self.warnings

    def __bool__(self) -> bool:  # pragma: no cover - удобство
        return self.is_valid


def validate_system_profile(data: Dict[str, Any]) -> ValidationResult:
    """Проверка шага 1."""
    errors: List[str] = []
    warnings: List[str] = []

    known_types = set(ReferenceLoader.get_system_types())
    system_types = [item for item in data.get("system_types") or [] if item]
    # Тип ИСПДн и признак обработки ПДн связаны в обе стороны
    if "ИСПДн" in system_types:
        data["processes_pd"] = True
    elif data.get("processes_pd") and "ИСПДн" not in system_types:
        system_types = system_types + ["ИСПДн"]
        data["system_types"] = system_types
    unknown = [item for item in system_types if item not in known_types]
    if unknown:
        errors.append(f"Неизвестные типы ИС: {', '.join(unknown)}")
    if not system_types:
        errors.append("Выберите хотя бы один тип информационной системы")

    known_technologies = set(ReferenceLoader.get_technologies())
    unknown_tech = [item for item in data.get("technologies") or [] if item not in known_technologies]
    if unknown_tech:
        errors.append(f"Неизвестные технологические признаки: {', '.join(unknown_tech)}")

    if data.get("processes_pd") and not data.get("pd_security_level"):
        errors.append("Для системы, обрабатывающей персональные данные, укажите уровень защищённости ПДн")

    level = data.get("pd_security_level")
    if level not in (None, "") and level not in VALID_PD_LEVELS:
        errors.append(f"Уровень защищённости ПДн должен быть в диапазоне 1-4, получено {level}")

    responsibility = (data.get("external_responsibility") or "").strip()
    if responsibility and len(responsibility) < 3:
        errors.append("Укажите организацию, несущую внешнюю ответственность, полностью")
    if data.get("processes_pd") and not system_types:
        warnings.append("Обработка ПДн указана, но тип ИС не выбран")

    return ValidationResult(errors, warnings)


def validate_violator_profile(data: Dict[str, Any]) -> ValidationResult:
    """Проверка шага 2."""
    errors: List[str] = []
    warnings: List[str] = []

    types = ReferenceLoader.get_violator_types()

    for category, field in (("external", "external_types"), ("internal", "internal_types")):
        for code in data.get(field) or []:
            item = types.get(code)
            if not item:
                errors.append(f"Неизвестный вид нарушителя: {code}")
            elif item.get("category") != category:
                errors.append(
                    f"Нарушитель «{item.get('name', code)}» относится к категории "
                    f"{'внешних' if item.get('category') == 'external' else 'внутренних'}"
                )

    if not (data.get("external_types") or data.get("internal_types")):
        warnings.append("Виды нарушителей не выбраны — перечень УБИ не будет ограничен по нарушителям")

    return ValidationResult(errors, warnings)


def validate_interfaces(interfaces: List[str]) -> ValidationResult:
    """Проверка шага 3."""
    errors: List[str] = []
    warnings: List[str] = []
    known = ReferenceLoader.get_interfaces()
    for code in interfaces:
        if code not in known:
            errors.append(f"Неизвестный тип интерфейса: {code}")
    if not interfaces:
        warnings.append("Интерфейсы не выбраны — перечень УБИ не будет ограничен по способам реализации")
    return ValidationResult(errors, warnings)


def validate_objects(selected_objects: List[str]) -> ValidationResult:
    """Проверка объектов воздействия."""
    errors: List[str] = []
    warnings: List[str] = []
    known = ReferenceLoader.get_objects()
    unknown = [code for code in selected_objects if code not in known]
    if unknown:
        errors.append(f"Неизвестные объекты воздействия: {', '.join(unknown)}")
    if not selected_objects:
        errors.append("Выберите хотя бы один объект воздействия")
    return ValidationResult(errors, warnings)


def validate_impacts(selected_impacts: List[str]) -> ValidationResult:
    """Проверка видов воздействия (В1-В7); выбор необязателен."""
    errors: List[str] = []
    warnings: List[str] = []
    known = ReferenceLoader.get_impacts()
    unknown = [code for code in selected_impacts if code not in known]
    if unknown:
        errors.append(f"Неизвестные виды воздействия: {', '.join(unknown)}")
    if not selected_impacts:
        warnings.append("Виды воздействия не выбраны — ограничение по ним не применяется")
    return ValidationResult(errors, warnings)


def validate_step4(selected_objects: List[str], selected_impacts: List[str]) -> ValidationResult:
    """Проверка шага 4: объекты обязательны, виды воздействия — фильтр."""
    objects_result = validate_objects(selected_objects)
    impacts_result = validate_impacts(selected_impacts)
    return ValidationResult(
        objects_result.errors + impacts_result.errors,
        objects_result.warnings + impacts_result.warnings,
    )


def validate_user_profile(profile: UserProfile) -> ValidationResult:
    """Полная проверка профиля (шаг 5)."""
    errors: List[str] = []
    warnings: List[str] = []

    for result in (
        validate_system_profile(profile.system.model_dump()),
        validate_violator_profile(profile.violators.model_dump()),
        validate_interfaces(profile.interfaces),
        validate_step4(profile.selected_objects, profile.selected_impacts),
    ):
        errors.extend(result.errors)
        warnings.extend(result.warnings)

    return ValidationResult(errors, warnings)


class WizardValidator:
    """Валидатор шагов wizard."""

    def validate_step(self, step: int, data: Dict[str, Any]) -> ValidationResult:
        """Проверить данные конкретного шага."""
        if step == 1:
            return validate_system_profile(data)
        if step == 2:
            return validate_violator_profile(data)
        if step == 3:
            return validate_interfaces(data.get("interfaces") or [])
        if step == 4:
            return validate_step4(data.get("selected_objects") or [], data.get("selected_impacts") or [])
        if step == 5:
            return ValidationResult([], ["Проверка выполняется при формировании отчёта"])
        return ValidationResult([f"Неверный номер шага: {step}"])
