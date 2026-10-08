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
title = Таблица 2 – УБИ
column = ubi_id | Идентификатор | 16
column = ubi_name | Наименование | 60
"""


def test_shipped_rules_file_is_valid():
    """Файл правил из поставки разбирается и содержит обе таблицы."""
    rules = load_rules()
    assert rules.title
    assert rules.table("table1").enabled and rules.table("table2").enabled
    assert rules.table("table1").columns, "в таблице 1 нет колонок"
    assert rules.table("table2").columns, "в таблице 2 нет колонок"
    fields = rules.table("table2").field_names
    assert "ubi_id" in fields and "consequences" in fields
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


def test_columns_can_be_disabled_and_reordered():
    """Отключение таблицы и изменение порядка колонок применяются."""
    text = """
    [table1]
    enabled = no
    column = name | Последствия
    [table2]
    enabled = yes
    column = ubi_name | Наименование
    column = ubi_id | Идентификатор
    """
    rules = parse_rules(text)
    assert rules.table("table1").enabled is False
    assert [c.field for c in rules.table("table2").columns] == ["ubi_name", "ubi_id"]


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
        ("[table2]\ncolumn = ubi_id", "колонка должна быть вида"),
        ("[table2]\ncolumn = unknown_field | X", "неизвестное поле"),
        ("[table2]\ncolumn = ubi_id | X | abc", "ширина колонки должна быть числом"),
        ("[table2]\ncolumn = ubi_id | X | 10 | middle", "выравнивание"),
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
