"""Правила формирования итоговых таблиц отчёта (``data/report-rules.txt``).

Файл правил — обычный текст, редактируется в блокноте без перезапуска сервиса.
Загрузчик разбирает его, проверяет имена полей и отдаёт структуру, по которой
строятся и страница предпросмотра, и выгрузки XLSX/DOCX.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import settings

# Поля, доступные в таблицах (см. data/report-rules.txt)
TABLE1_FIELDS = ("row_number", "code", "risk", "name", "conditions")
TABLE2_FIELDS = (
    "ubi_id",
    "ubi_name",
    "violator_internal",
    "violator_external",
    "objects",
    "impacts",
    "methods",
    "consequences",
    "tactics",
    "techniques",
    "notes",
)

ALIGNMENTS = ("left", "center", "right")
RULES_RELATIVE_PATH = Path("report-rules.txt")


class ReportRulesError(Exception):
    """Ошибка в файле правил отчёта (сообщение показывается пользователю)."""


@dataclass
class Column:
    """Колонка таблицы отчёта."""

    field: str
    header: str
    width: int = 20
    align: str = "left"


@dataclass
class TableRules:
    """Правила одной таблицы отчёта."""

    key: str
    enabled: bool = True
    title: str = ""
    columns: List[Column] = field(default_factory=list)

    @property
    def field_names(self) -> List[str]:
        return [column.field for column in self.columns]


@dataclass
class ReportRules:
    """Полный набор правил отчёта."""

    title: str
    show_profile: bool
    tables: Dict[str, TableRules]
    source_path: Optional[Path] = None
    warnings: List[str] = field(default_factory=list)

    def table(self, key: str) -> TableRules:
        return self.tables.get(key) or TableRules(key=key, enabled=False)


def rules_path() -> Path:
    """Путь к файлу правил отчёта."""
    return Path(settings.data_dir) / RULES_RELATIVE_PATH


def _parse_bool(value: str, default: bool = True) -> bool:
    value = (value or "").strip().lower()
    if value in ("yes", "да", "true", "1", "on"):
        return True
    if value in ("no", "нет", "false", "0", "off"):
        return False
    return default


def parse_rules(text: str, path: Optional[Path] = None) -> ReportRules:
    """Разобрать содержимое файла правил.

    Raises:
        ReportRulesError: если обнаружена неизвестная секция, поле или
            синтаксическая ошибка (сообщение содержит номер строки).
    """
    warnings: List[str] = []
    sections: Dict[str, Dict[str, object]] = {
        "report": {"title": "Модель угроз безопасности информации", "show_profile": True},
        "table1": {"enabled": True, "title": "", "columns": []},
        "table2": {"enabled": True, "title": "", "columns": []},
    }
    current: Optional[str] = None
    fields_by_table = {"table1": TABLE1_FIELDS, "table2": TABLE2_FIELDS}

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section not in sections:
                raise ReportRulesError(
                    f"строка {number}: неизвестный раздел [{section}]; "
                    f"допустимы [report], [table1], [table2]"
                )
            current = section
            continue
        if current is None:
            raise ReportRulesError(f"строка {number}: параметр вне раздела (ожидается [report], [table1] или [table2])")
        if "=" not in line:
            raise ReportRulesError(f"строка {number}: ожидается «параметр = значение»")
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()

        if current == "report":
            if key == "title":
                sections["report"]["title"] = value
            elif key == "show_profile":
                sections["report"]["show_profile"] = _parse_bool(value)
            else:
                raise ReportRulesError(f"строка {number}: неизвестный параметр «{key}» в разделе [report]")
            continue

        if key == "enabled":
            sections[current]["enabled"] = _parse_bool(value)
            continue
        if key == "title":
            sections[current]["title"] = value
            continue
        if key != "column":
            raise ReportRulesError(f"строка {number}: неизвестный параметр «{key}» в разделе [{current}]")

        parts = [part.strip() for part in value.split("|")]
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ReportRulesError(
                f"строка {number}: колонка должна быть вида "
                f"column = поле | Заголовок | ширина | выравнивание"
            )
        field_name = parts[0].lower()
        if field_name not in fields_by_table[current]:
            raise ReportRulesError(
                f"строка {number}: неизвестное поле «{parts[0]}» в разделе [{current}]; "
                f"допустимы: {', '.join(fields_by_table[current])}"
            )
        width = 20
        if len(parts) >= 3 and parts[2]:
            try:
                width = int(parts[2])
            except ValueError:
                raise ReportRulesError(f"строка {number}: ширина колонки должна быть числом, получено «{parts[2]}»")
            if width <= 0:
                raise ReportRulesError(f"строка {number}: ширина колонки должна быть больше нуля")
        align = "left"
        if len(parts) >= 4 and parts[3]:
            align = parts[3].lower()
            if align not in ALIGNMENTS:
                raise ReportRulesError(
                    f"строка {number}: выравнивание «{parts[3]}» не поддерживается; "
                    f"допустимы: {', '.join(ALIGNMENTS)}"
                )
        columns = sections[current]["columns"]
        columns.append(Column(field=field_name, header=parts[1], width=width, align=align))

    for table_key in ("table1", "table2"):
        columns = sections[table_key]["columns"]
        if not columns:
            warnings.append(f"[{table_key}] не содержит ни одной колонки — таблица не будет сформирована")
        if not sections[table_key]["title"]:
            sections[table_key]["title"] = f"Таблица {table_key[-1]}"

    # повторяющиеся поля — почти всегда опечатка при правке файла
    for table_key in ("table1", "table2"):
        names = [column.field for column in sections[table_key]["columns"]]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            warnings.append(f"[{table_key}] поля повторяются и будут выведены дважды: {duplicates}")

    return ReportRules(
        title=str(sections["report"]["title"]),
        show_profile=bool(sections["report"]["show_profile"]),
        tables={
            "table1": TableRules(
                key="table1",
                enabled=bool(sections["table1"]["enabled"]),
                title=str(sections["table1"]["title"]),
                columns=list(sections["table1"]["columns"]),
            ),
            "table2": TableRules(
                key="table2",
                enabled=bool(sections["table2"]["enabled"]),
                title=str(sections["table2"]["title"]),
                columns=list(sections["table2"]["columns"]),
            ),
        },
        source_path=path,
        warnings=warnings,
    )


def load_rules(path: Optional[Path] = None, use_cache: bool = False) -> ReportRules:
    """Загрузить правила отчёта из файла.

    Файл перечитывается при каждом обращении (правки в блокноте применяются сразу).
    """
    target = path or rules_path()
    if not target.exists():
        raise ReportRulesError(
            f"файл правил отчёта не найден: {target}. "
            f"Восстановите его из репозитория (data/report-rules.txt)"
        )
    with open(target, "r", encoding="utf-8") as handle:
        return parse_rules(handle.read(), path=target)


def row_values(row: Dict[str, object], columns: List[Column], row_number: Optional[int] = None) -> List[str]:
    """Значения строки отчёта в порядке колонок правил."""
    values: List[str] = []
    for column in columns:
        if column.field == "row_number":
            values.append(str(row_number if row_number is not None else ""))
        else:
            values.append(str(row.get(column.field, "") or ""))
    return values


def build_tables(report, rules: ReportRules) -> Dict[str, Dict[str, object]]:
    """Собрать таблицы отчёта по правилам: заголовки и готовые строки.

    Один и тот же результат используется страницей предпросмотра и выгрузками,
    поэтому предпросмотр всегда совпадает с экспортом.
    """
    tables: Dict[str, Dict[str, object]] = {}

    table1 = rules.table("table1")
    if table1.enabled and table1.columns:
        rows = [
            row_values(item.model_dump(), table1.columns, row_number=index)
            for index, item in enumerate(report.risk_table, start=1)
        ]
        tables["table1"] = {"title": table1.title, "table": table1, "rows": rows}

    table2 = rules.table("table2")
    if table2.enabled and table2.columns:
        rows = [row_values(item.model_dump(), table2.columns) for item in report.threats]
        tables["table2"] = {"title": table2.title, "table": table2, "rows": rows}

    return tables
