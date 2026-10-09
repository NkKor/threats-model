"""Тесты правил формирования итоговых таблиц (data/report-rules.txt)."""

from __future__ import annotations

import pytest

from app.core.report_rules import ReportRulesError, load_rules, parse_rules, row_values

VALID = """
[report]
title = Тестовый отчёт
show_profile = no

[table1]
enabled = yes
title = Таблица 1 – Последствия
column = row_number | № | 8 | center
column = name | Последствия | 60

[table2]
enabled = yes
title = Таблица 2 – Воздействия
column = consequence | Последствия | 60
column = objects | Объекты | 30
"""


def test_shipped_rules_file_is_valid():
    """Файл правил из поставки разбирается и содержит все семь таблиц."""
    rules = load_rules()
    assert rules.title
    for key in ("table1", "table2", "table3", "table4", "table5", "table6", "table7"):
        table = rules.table(key)
        assert table.enabled, f"{key} отключена"
        assert table.columns, f"{key}: нет колонок"
    assert "ubi_id" in rules.table("table7").field_names
    assert "consequences" in rules.table("table7").field_names
    assert rules.table("table5").has_groups
    assert rules.table("table7").has_groups
    assert rules.table("table7").header_height == 2
    assert not rules.warnings, rules.warnings


def test_parse_rules_reads_columns_and_options():
    """Разбор корректного файла: заголовок, режим показа профиля, колонки."""
    rules = parse_rules(VALID)
    assert rules.title == "Тестовый отчёт"
    assert rules.show_profile is False
    table1 = rules.table("table1")
    assert [column.field for column in table1.columns] == ["row_number", "name"]
    assert table1.columns[0].align == "center"
    assert table1.columns[0].width == 8
    assert rules.table("table2").columns[1].align == "left"


def test_group_headers_are_merged():
    """Групповое поле формирует двухуровневую шапку с объединениями."""
    text = """
    [table7]
    column = ubi_id | Идентификатор УБИ | 14 | center
    column = violator_internal | Внутренний | 12 | center | Уровень возможностей нарушителей
    column = violator_external | Внешний | 12 | center | Уровень возможностей нарушителей
    column = notes | Примечания | 20
    """
    table = parse_rules(text).table("table7")
    assert table.has_groups
    header_rows = table.header_rows()
    assert len(header_rows) == 2
    top = header_rows[0]
    assert [(cell.text, cell.colspan, cell.rowspan) for cell in top] == [
        ("Идентификатор УБИ", 1, 2),
        ("Уровень возможностей нарушителей", 2, 1),
        ("Примечания", 1, 2),
    ]
    assert [cell.text for cell in header_rows[1]] == ["Внутренний", "Внешний"]


def test_columns_can_be_disabled_and_reordered():
    """Отключение таблицы и изменение порядка колонок применяются."""
    text = """
    [table1]
    enabled = no
    column = name | Последствия
    [table7]
    enabled = yes
    column = ubi_name | Наименование
    column = ubi_id | Идентификатор
    """
    rules = parse_rules(text)
    assert rules.table("table1").enabled is False
    assert [c.field for c in rules.table("table7").columns] == ["ubi_name", "ubi_id"]


def test_row_values_follow_column_order():
    """Значения строки собираются в порядке колонок правил."""
    rules = parse_rules(VALID)
    row = {"name": "Простой ИС", "code": "у2.22"}
    assert row_values(row, rules.table("table1").columns, row_number=7) == ["7", "Простой ИС"]


@pytest.mark.parametrize(
    "text, expected",
    [
        ("[unknown]\ncolumn = a | b", "неизвестный раздел"),
        ("column = ubi_id | X", "вне раздела"),
        ("[table2]\ncolumn = objects", "колонка должна быть вида"),
        ("[table2]\ncolumn = unknown_field | X", "неизвестное поле"),
        ("[table2]\ncolumn = objects | X | abc", "ширина колонки должна быть числом"),
        ("[table2]\ncolumn = objects | X | 10 | middle", "выравнивание"),
        ("[table2]\nfoo = bar", "неизвестный параметр"),
        ("[report]\nfoo = bar", "неизвестный параметр"),
    ],
)
def test_invalid_rules_report_precise_error(text, expected):
    """Ошибки в правилах описываются понятным сообщением с номером строки."""
    with pytest.raises(ReportRulesError) as error:
        parse_rules(text)
    assert expected in str(error.value)
    assert "строка" in str(error.value)


def test_missing_file_reports_path(tmp_path):
    """Отсутствие файла правил даёт понятную ошибку."""
    with pytest.raises(ReportRulesError) as error:
        load_rules(tmp_path / "no-such-file.txt")
    assert "не найден" in str(error.value)
