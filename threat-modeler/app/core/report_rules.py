"""Правила формирования итоговых таблиц отчёта (``data/report-rules.txt``).

Файл правил — обычный текст, редактируется в блокноте без перезапуска сервиса.
Загрузчик разбирает его, проверяет имена полей и отдаёт структуру, по которой
строятся и страница предпросмотра, и выгрузки XLSX/DOCX.

Формат колонки::

    column = поле | Заголовок | ширина | выравнивание | Группа

Пятое поле «Группа» необязательно. Если оно задано, шапка таблицы становится
двухуровневой: соседние колонки с одинаковой группой объединяются по горизонтали
(над ними выводится общий заголовок), а колонки без группы объединяются по
вертикали на обе строки.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from app.config import settings

# Поля, доступные в таблицах (см. data/report-rules.txt)
TABLE_FIELDS: Dict[str, Tuple[str, ...]] = {
    "table1": ("row_number", "code", "risk", "risk_name", "risk_title", "name", "conditions"),
    "table2": ("consequence", "objects", "impacts"),
    "table3": ("row_number", "violator", "category", "goals"),
    "table4": ("row_number", "level", "level_name", "capabilities", "violators"),
    "table5": ("violator", "damage_physical", "damage_legal", "damage_state", "correspondence"),
    "table6": ("row_number", "violator", "category", "objects", "interfaces", "methods"),
    "table7": (
        "ubi_id",
        "ubi_name",
        "violator_internal",
        "violator_external",
        "objects",
        "methods",
        "impacts",
        "consequences",
        "tactics",
        "techniques",
        "notes",
    ),
}
TABLE_KEYS: Tuple[str, ...] = tuple(TABLE_FIELDS)

# Совместимость с прежним API
TABLE1_FIELDS = TABLE_FIELDS["table1"]
TABLE2_FIELDS = TABLE_FIELDS["table2"]

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
    group: Optional[str] = None


@dataclass
class HeaderCell:
    """Ячейка шапки таблицы (с учётом объединений).

    ``col`` — номер колонки сетки (0-based), с которой начинается ячейка.
    Для второй строки шапки перечисляются только ячейки сгруппированных колонок.
    """

    text: str
    colspan: int = 1
    rowspan: int = 1
    col: int = 0


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

    @property
    def has_groups(self) -> bool:
        return any(column.group for column in self.columns)

    def header_rows(self) -> List[List[HeaderCell]]:
        """Строки шапки таблицы: одна либо две (с групповым заголовком)."""
        if not self.columns:
            return [[]]
        if not self.has_groups:
            return [
                [HeaderCell(column.header, col=index) for index, column in enumerate(self.columns)]
            ]

        top: List[HeaderCell] = []
        bottom: List[HeaderCell] = []
        index = 0
        total = len(self.columns)
        while index < total:
            column = self.columns[index]
            if column.group:
                end = index
                while end < total and self.columns[end].group == column.group:
                    end += 1
                top.append(HeaderCell(column.group, colspan=end - index, rowspan=1, col=index))
                for grouped in range(index, end):
                    bottom.append(HeaderCell(self.columns[grouped].header, col=grouped))
                index = end
            else:
                top.append(HeaderCell(column.header, colspan=1, rowspan=2, col=index))
                index += 1
        return [top, bottom]

    @property
    def header_height(self) -> int:
        return len(self.header_rows())


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
    }
    for key in TABLE_KEYS:
        sections[key] = {"enabled": True, "title": "", "columns": []}

    current: Optional[str] = None
    allowed_sections = ("report",) + TABLE_KEYS

    for number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section not in sections:
                raise ReportRulesError(
                    f"строка {number}: неизвестный раздел [{section}]; "
                    f"допустимы {', '.join('[' + key + ']' for key in allowed_sections)}"
                )
            current = section
            continue
        if current is None:
            raise ReportRulesError(
                f"строка {number}: параметр вне раздела "
                f"(ожидается {', '.join('[' + key + ']' for key in allowed_sections)})"
            )
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
                f"column = поле | Заголовок | ширина | выравнивание | Группа"
            )
        field_name = parts[0].lower()
        if field_name not in TABLE_FIELDS[current]:
            raise ReportRulesError(
                f"строка {number}: неизвестное поле «{parts[0]}» в разделе [{current}]; "
                f"допустимы: {', '.join(TABLE_FIELDS[current])}"
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
        group = None
        if len(parts) >= 5 and parts[4] and parts[4] not in ("-", "—", "–"):
            group = parts[4]
        columns = sections[current]["columns"]
        columns.append(Column(field=field_name, header=parts[1], width=width, align=align, group=group))

    for table_key in TABLE_KEYS:
        columns = sections[table_key]["columns"]
        if not columns:
            warnings.append(f"[{table_key}] не содержит ни одной колонки — таблица не будет сформирована")
        if not sections[table_key]["title"]:
            sections[table_key]["title"] = f"Таблица {table_key[-1]}"

    # повторяющиеся поля — почти всегда опечатка при правке файла
    for table_key in TABLE_KEYS:
        names = [column.field for column in sections[table_key]["columns"]]
        duplicates = sorted({name for name in names if names.count(name) > 1})
        if duplicates:
            warnings.append(f"[{table_key}] поля повторяются и будут выведены дважды: {duplicates}")

    return ReportRules(
        title=str(sections["report"]["title"]),
        show_profile=bool(sections["report"]["show_profile"]),
        tables={
            key: TableRules(
                key=key,
                enabled=bool(sections[key]["enabled"]),
                title=str(sections[key]["title"]),
                columns=list(sections[key]["columns"]),
            )
            for key in TABLE_KEYS
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


def _rows_for(report, key: str) -> List[Dict[str, object]]:
    """Строки таблицы: из ``table_rows`` отчёта или из совместимых полей."""
    table_rows = getattr(report, "table_rows", None)
    if table_rows and key in table_rows:
        return [dict(row) for row in table_rows[key]]
    if key == "table1":
        return [item.model_dump() for item in report.risk_table]
    if key == "table7":
        return [item.model_dump() for item in report.threats]
    return []


def build_tables(report, rules: ReportRules) -> Dict[str, Dict[str, object]]:
    """Собрать таблицы отчёта по правилам: заголовки и готовые строки.

    Один и тот же результат используется страницей предпросмотра и выгрузками,
    поэтому предпросмотр всегда совпадает с экспортом.
    """
    tables: Dict[str, Dict[str, object]] = {}
    for key in TABLE_KEYS:
        table = rules.table(key)
        if not (table.enabled and table.columns):
            continue
        rows = [
            row_values(row, table.columns, row_number=index)
            for index, row in enumerate(_rows_for(report, key), start=1)
        ]
        tables[key] = {
            "key": key,
            "title": table.title,
            "table": table,
            "rows": rows,
            "header_rows": table.header_rows(),
        }
    return tables
