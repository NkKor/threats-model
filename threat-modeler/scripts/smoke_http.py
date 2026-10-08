#!/usr/bin/env python3
"""Проверка развёрнутого сервиса по HTTP: сквозной проход wizard и экспорт отчёта.

Запуск (сервис уже должен быть поднят)::

    python scripts/smoke_http.py
    python scripts/smoke_http.py --base http://127.0.0.1:8080

Скрипт проходит шаги 1-4, проверяет предпросмотр отчёта на шаге 5 и сохраняет
выгруженные XLSX/DOCX в каталог ``reports/``.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse
from pathlib import Path

import httpx

DEFAULT_BASE = "http://127.0.0.1:8080"


def csrf(html: str) -> str:
    """Извлечь CSRF-токен из HTML-формы."""
    match = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if not match:
        raise SystemExit("CSRF-токен не найден в форме — сервис отвечает не той страницей")
    return match.group(1)


def post_form(client: httpx.Client, url: str, pairs) -> httpx.Response:
    """Отправить форму с повторяющимися полями."""
    body = urllib.parse.urlencode(pairs).encode()
    return client.post(url, content=body, headers={"Content-Type": "application/x-www-form-urlencoded"})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Проверка развёрнутого сервиса")
    parser.add_argument("--base", default=DEFAULT_BASE, help="Базовый адрес сервиса")
    parser.add_argument("--out", default="reports", help="Каталог для выгруженных отчётов")
    args = parser.parse_args(argv)

    failures = 0
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    def check(condition: bool, message: str) -> None:
        nonlocal failures
        print(("  OK  " if condition else " FAIL ") + message)
        if not condition:
            failures += 1

    with httpx.Client(base_url=args.base, timeout=60.0, follow_redirects=False) as client:
        health = client.get("/health")
        check(health.status_code == 200, f"/health -> {health.status_code}")

        page = client.get("/api/wizard/")
        check(page.status_code == 200 and "Типы информационных систем" in page.text, "шаг 1 отрисован")
        token = csrf(page.text)

        response = post_form(
            client,
            "/api/wizard/step1",
            [
                ("csrf_token", token),
                ("system_types", "ПДн"),
                ("system_types", "ГИС"),
                ("technologies", "cloud"),
                ("technologies", "virtualization"),
                ("processes_pd", "on"),
                ("pd_security_level", "2"),
                ("has_internet_access", "on"),
            ],
        )
        check(response.status_code == 303, f"шаг 1 -> {response.status_code}")

        page = client.get("/api/wizard/step/2")
        response = post_form(
            client,
            "/api/wizard/step2",
            [
                ("csrf_token", csrf(page.text)),
                ("external_types", "otdelnye_fizicheskie_lica_hakery"),
                ("internal_types", "avtorizovannye_polzovateli_sistem_i_setey"),
                ("external_level", "Н3"),
                ("internal_level", "Н2"),
            ],
        )
        check(response.status_code == 303, f"шаг 2 -> {response.status_code}")

        page = client.get("/api/wizard/step/3")
        response = post_form(
            client,
            "/api/wizard/step3",
            [
                ("csrf_token", csrf(page.text)),
                ("interfaces", "external_network"),
                ("interfaces", "web"),
                ("interfaces", "user"),
            ],
        )
        check(response.status_code == 303, f"шаг 3 -> {response.status_code}")

        page = client.get("/api/wizard/step/4")
        response = post_form(
            client,
            "/api/wizard/step4",
            [
                ("csrf_token", csrf(page.text)),
                ("selected_objects", "О4"),
                ("selected_objects", "О23"),
                ("selected_objects", "О31"),
                ("selected_objects", "О19"),
                ("selected_objects", "О5"),
                ("selected_impacts", "В1"),
                ("selected_impacts", "В2"),
                ("selected_impacts", "В3"),
            ],
        )
        check(response.status_code == 303, f"шаг 4 -> {response.status_code}")

        report_page = client.get("/api/wizard/step/5")
        check("Таблица 1" in report_page.text and "Таблица 2" in report_page.text, "предпросмотр содержит таблицы 1 и 2")
        check("УБИ." in report_page.text, "предпросмотр содержит строки УБИ")
        check("Виды воздействия" in report_page.text, "предпросмотр содержит виды воздействия")
        check('id="threat-search"' in report_page.text, "на странице отчёта есть поиск по перечню")
        check("Очистить данные" in report_page.text, "на странице есть кнопка очистки данных")

        for extension in ("xlsx", "docx"):
            export = client.get(f"/api/reports/export.{extension}")
            ok = export.status_code == 200 and export.content[:4] == b"PK\x03\x04"
            check(ok, f"экспорт {extension}: {export.status_code}, {len(export.content)} байт")
            if ok:
                (out_dir / f"threat_model_report.{extension}").write_bytes(export.content)

        references = client.get("/api/reference/")
        counts = references.json().get("counts", {}) if references.status_code == 200 else {}
        check(references.status_code == 200, f"справочники -> {references.status_code}")
        check(counts.get("objects") == 38 and counts.get("threats", counts.get("violator_types")) is not None,
              f"состав справочников: объектов {counts.get('objects')}, уровней {counts.get('violator_levels')}")

        # «Очистить данные»: после очистки форма пустая, данные не восстанавливаются
        clean = post_form(client, "/api/wizard/clear", [("csrf_token", csrf(report_page.text))])
        check(clean.status_code == 303, f"очистка данных -> {clean.status_code}")
        fresh = client.get("/api/wizard/")
        check(fresh.status_code == 200 and "checked" not in fresh.text, "после очистки форма пустая")
        check(client.get("/api/reports/export.xlsx").status_code == 400, "после очистки экспорт недоступен")

    print("\nИтог:", "все проверки пройдены" if not failures else f"ошибок: {failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
