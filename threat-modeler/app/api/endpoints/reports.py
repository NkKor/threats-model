"""Экспорт итогового отчёта: XLSX и DOCX.

Экспорт выполняется только по явной команде пользователя (кнопки
«Экспорт в таблицу» / «Экспорт в документ»): сервис не сохраняет отчёт ни в базе,
ни в файловой системе. Состав и заголовки таблиц берутся из
``data/report-rules.txt``, поэтому предпросмотр и выгрузка всегда совпадают.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db
from app.api.endpoints.wizard import build_current_report, report_context
from app.core.report_rules import ReportRulesError, build_tables, load_rules
from app.utils.report_export import build_docx, build_xlsx

router = APIRouter(prefix="/api/reports", tags=["reports"])

XLSX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


def _prepare(profile, report):
    """Загрузить правила отчёта и собрать таблицы."""
    try:
        rules = load_rules()
    except ReportRulesError as error:
        raise HTTPException(status_code=500, detail=f"Правила отчёта: {error}")
    tables = build_tables(report, rules)
    if not tables:
        raise HTTPException(status_code=400, detail="В report-rules.txt не включена ни одна таблица")
    return rules, tables


@router.get("/export.xlsx")
@router.get("/export")
async def export_xlsx(request: Request, db: AsyncSession = Depends(get_db)):
    """Экспорт отчёта в XLSX по правилам report-rules.txt."""
    profile, _, report = await build_current_report(request, db)
    rules, tables = _prepare(profile, report)
    return Response(
        content=build_xlsx(report, tables, rules),
        media_type=XLSX_MEDIA_TYPE,
        headers={"Content-Disposition": 'attachment; filename="threat_model_report.xlsx"'},
    )


@router.get("/export.docx")
async def export_docx(request: Request, db: AsyncSession = Depends(get_db)):
    """Экспорт отчёта в DOCX по правилам report-rules.txt."""
    profile, _, report = await build_current_report(request, db)
    rules, tables = _prepare(profile, report)
    return Response(
        content=build_docx(report, tables, rules),
        media_type=DOCX_MEDIA_TYPE,
        headers={"Content-Disposition": 'attachment; filename="threat_model_report.docx"'},
    )
