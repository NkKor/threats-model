"""Загрузка канонических справочников из ``data/reference``.

Справочники формируются скриптом ``scripts/import_sources.py`` из источников
рабочего каталога, поэтому приложение читает их в режиме «только чтение» и
кэширует в памяти процесса.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

REFERENCE_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "reference"


class ReferenceLoader:
    """Загрузчик и кэш справочников."""

    _cache: Dict[str, Any] = {}

    # ------------------------------------------------------------------ #
    # Низкоуровневый доступ
    # ------------------------------------------------------------------ #

    @classmethod
    def load_yaml(cls, filename: str) -> Dict[str, Any]:
        """Загрузить YAML-файл справочника (с кэшированием)."""
        if filename in cls._cache:
            return cls._cache[filename]
        filepath = REFERENCE_DIR / filename
        if not filepath.exists():
            raise FileNotFoundError(
                f"Справочник не найден: {filepath}. Запустите: python -m scripts.import_sources"
            )
        with open(filepath, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        cls._cache[filename] = data
        return data

    @classmethod
    def clear_cache(cls) -> None:
        """Сбросить кэш справочников."""
        cls._cache.clear()

    # ------------------------------------------------------------------ #
    # Справочники
    # ------------------------------------------------------------------ #

    @classmethod
    def get_objects(cls) -> Dict[str, Dict[str, Any]]:
        """Объекты воздействия (38 позиций)."""
        return cls.load_yaml("objects.yaml").get("objects", {})

    @classmethod
    def get_methods(cls) -> Dict[str, Dict[str, Any]]:
        """Способы реализации (СП1-СП9)."""
        return cls.load_yaml("methods.yaml").get("methods", {})

    @classmethod
    def get_impacts(cls) -> Dict[str, Dict[str, Any]]:
        """Виды воздействия (В1-В7)."""
        return cls.load_yaml("impacts.yaml").get("impacts", {})

    @classmethod
    def get_consequences(cls) -> Dict[str, Dict[str, Any]]:
        """Негативные последствия (уX.Y)."""
        return cls.load_yaml("consequences.yaml").get("consequences", {})

    @classmethod
    def get_risk_types(cls) -> Dict[str, Dict[str, Any]]:
        """Виды риска (У1-У3)."""
        return cls.load_yaml("consequences.yaml").get("risk_types", {})

    @classmethod
    def get_system_types(cls) -> Dict[str, Dict[str, Any]]:
        """Типы информационных систем."""
        return cls.load_yaml("system_types.yaml").get("system_types", {})

    @classmethod
    def get_violator_types(cls) -> Dict[str, Dict[str, Any]]:
        """Виды нарушителей."""
        return cls.load_yaml("violators.yaml").get("violator_types", {})

    @classmethod
    def get_violator_levels(cls) -> Dict[str, Dict[str, Any]]:
        """Уровни возможностей нарушителей (Н1-Н4)."""
        return cls.load_yaml("violators.yaml").get("violator_levels", {})

    @classmethod
    def get_violator_goals_table(cls) -> List[Dict[str, Any]]:
        """Таблица целей нарушителей (источник таблицы 5 отчёта)."""
        return cls.load_yaml("violators.yaml").get("violator_goals_table", [])

    @classmethod
    def get_violator_name(cls, code: str) -> str:
        """Наименование вида нарушителя по коду."""
        item = cls.get_violator_types().get(code) or {}
        return item.get("name", code)

    @classmethod
    def get_tactics(cls) -> Dict[str, Dict[str, Any]]:
        """Тактики (Т1-Т10) с техниками."""
        return cls.load_yaml("tactics.yaml").get("tactics", {})

    @classmethod
    def get_interfaces(cls) -> Dict[str, Dict[str, Any]]:
        """Типы интерфейсов и доступные через них способы реализации."""
        return cls.load_yaml("interfaces.yaml").get("interfaces", {})

    @classmethod
    def get_technologies(cls) -> Dict[str, Dict[str, Any]]:
        """Технологические признаки системы и соответствующие объекты."""
        return cls.load_yaml("technologies.yaml").get("technologies", {})

    @classmethod
    def get_consequence_impacts(cls) -> Dict[str, List[str]]:
        """Соответствие «негативное последствие -> виды воздействия» (таблица 3 Методики)."""
        return cls.load_yaml("consequence_impacts.yaml").get("consequence_impacts", {})

    @classmethod
    def get_consequence_impact_mapping(cls) -> Dict[str, Dict[str, Any]]:
        """Детали сопоставления последствий с таблицей 3 (для проверки и API)."""
        return cls.load_yaml("consequence_impacts.yaml").get("mapping", {})

    # ------------------------------------------------------------------ #
    # Производные выборки
    # ------------------------------------------------------------------ #

    @classmethod
    def consequences_for_system_types(cls, system_types: List[str]) -> List[str]:
        """Коды последствий, применимых для выбранных типов ИС."""
        if not system_types:
            return []
        selected = set(system_types)
        result: List[str] = []
        for code, item in cls.get_consequences().items():
            if selected & set(item.get("system_types") or []):
                result.append(code)
        return result

    @classmethod
    def methods_for_interfaces(cls, interfaces: List[str]) -> List[str]:
        """Способы реализации, доступные через выбранные типы интерфейсов."""
        if not interfaces:
            return []
        available: List[str] = []
        for code in interfaces:
            item = cls.get_interfaces().get(code)
            if not item:
                continue
            for method in item.get("methods") or []:
                if method not in available:
                    available.append(method)
        return available

    @classmethod
    def objects_for_technologies(cls, technologies: List[str]) -> List[str]:
        """Объекты воздействия, соответствующие выбранным технологиям."""
        result: List[str] = []
        for code in technologies:
            item = cls.get_technologies().get(code)
            if not item:
                continue
            for obj in item.get("objects") or []:
                if obj not in result:
                    result.append(obj)
        return result

    @classmethod
    def impacts_for_consequences(cls, codes: List[str]) -> List[str]:
        """Виды воздействия, соответствующие перечню негативных последствий.

        Виды воздействия выводятся через таблицу 3 Методики, поэтому для части
        последствий (риск-группы У1/У3 и отдельных позиций У2) соответствие
        отсутствует — такие коды просто не влияют на результат.
        """
        mapping = cls.get_consequence_impacts()
        result: List[str] = []
        for code in codes:
            for impact in mapping.get(code, []):
                if impact not in result:
                    result.append(impact)
        return sorted(result, key=lambda item: int(item[1:]))

    @classmethod
    def get_all_references(cls) -> Dict[str, Any]:
        """Все справочники одним словарём (для API)."""
        return {
            "objects": cls.get_objects(),
            "methods": cls.get_methods(),
            "impacts": cls.get_impacts(),
            "consequences": cls.get_consequences(),
            "risk_types": cls.get_risk_types(),
            "system_types": cls.get_system_types(),
            "violator_types": cls.get_violator_types(),
            "violator_levels": cls.get_violator_levels(),
            "violator_goals_table": cls.get_violator_goals_table(),
            "tactics": cls.get_tactics(),
            "interfaces": cls.get_interfaces(),
            "technologies": cls.get_technologies(),
            "consequence_impacts": cls.get_consequence_impacts(),
        }


# ---------------------------------------------------------------------- #
# Удобные функции-обёртки
# ---------------------------------------------------------------------- #

def get_object_name(code: str) -> str:
    item = ReferenceLoader.get_objects().get(code)
    return item.get("name", code) if item else code


def get_method_name(code: str) -> str:
    item = ReferenceLoader.get_methods().get(code)
    return item.get("name", code) if item else code


def get_consequence_name(code: str) -> str:
    item = ReferenceLoader.get_consequences().get(code)
    return item.get("name", code) if item else code


def get_consequence_risk(code: str) -> Optional[str]:
    item = ReferenceLoader.get_consequences().get(code)
    return item.get("risk") if item else None


def get_tactic_name(code: str) -> str:
    item = ReferenceLoader.get_tactics().get(code)
    return item.get("name", code) if item else code


def get_technique_name(code: str) -> str:
    for tactic in ReferenceLoader.get_tactics().values():
        technique = (tactic.get("techniques") or {}).get(code)
        if technique:
            return technique.get("name", code)
    return code


def get_impact_name(code: str) -> str:
    item = ReferenceLoader.get_impacts().get(code)
    return item.get("name", code) if item else code


def get_violator_level_name(code: str) -> str:
    item = ReferenceLoader.get_violator_levels().get(code)
    return item.get("name", code) if item else code


def format_codes(codes: List[str], namer) -> str:
    """Собрать «код — название» через точку с запятой для отчёта."""
    parts = []
    for code in codes:
        name = namer(code)
        parts.append(f"{code} ({name})" if name and name != code else code)
    return "; ".join(parts)


def format_code_list(codes) -> str:
    """Список только кодов через запятую (компактный вид колонки отчёта).

    Порядок естественный: ``Т2`` раньше ``Т10``, ``Т2.5`` раньше ``Т2.10`` —
    так перечень читается как «Т1, Т2, Т3» и не зависит от порядка обхода пар.
    """
    def sort_key(code: str):
        numbers = re.findall(r"\d+", code)
        return tuple(int(number) for number in numbers) if numbers else (0,)

    unique = {code for code in codes if code}
    return ", ".join(sorted(unique, key=sort_key))
