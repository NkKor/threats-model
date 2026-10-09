"""Wizard: пошаговый опрос пользователя, предпросмотр и экспорт отчёта.

Данные опроса не сохраняются на сервере: они живут только в подписанной
cookie-сессии браузера и исчезают при очистке кэша или нажатии кнопки
«Очистить данные». В базу данных профиль и отчёт не записываются.
"""

from __future__ import annotations

import secrets
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db
from app.core.correlation import build_report, compute_category_levels, filter_threats
from app.core.reference_loader import ReferenceLoader
from app.core.report_rules import ReportRulesError, build_tables, load_rules
from app.core.validator import validate_user_profile
from app.db.queries import get_all_objects, get_all_threats
from app.models.schemas import UserProfile

router = APIRouter(prefix="/api/wizard", tags=["wizard"])

SESSION_COOKIE = "threat_modeler_session"

STEP_TEMPLATES = {
    1: "wizard/step1_system.html",
    2: "wizard/step2_violators.html",
    3: "wizard/step3_interfaces.html",
    4: "wizard/step4_objects.html",
    5: "wizard/step5_report.html",
}


# --------------------------------------------------------------------------- #
# Работа с сессией
# --------------------------------------------------------------------------- #

def get_csrf_token(request: Request) -> str:
    """Получить (или создать) CSRF-токен текущей сессии."""
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def check_csrf(request: Request, form_data: Any) -> None:
    """Проверить CSRF-токен формы."""
    expected = request.session.get("csrf_token")
    provided = (form_data.get("csrf_token") or "") if form_data is not None else ""
    if not expected or not secrets.compare_digest(str(provided), str(expected)):
        raise HTTPException(status_code=403, detail="Сессия устарела. Обновите страницу и повторите ввод.")


def get_profile_data(request: Request) -> Dict[str, Any]:
    """Данные профиля из сессии."""
    return dict(request.session.get("user_profile") or {})


def save_profile_data(request: Request, data: Dict[str, Any]) -> None:
    """Сохранить профиль в сессии."""
    request.session["user_profile"] = data


def build_profile(data: Dict[str, Any]) -> UserProfile:
    """Собрать модель профиля из данных сессии."""
    return UserProfile(**{key: value for key, value in data.items() if key != "csrf_token"})


def base_context(request: Request, step: int, **extra: Any) -> Dict[str, Any]:
    """Базовый контекст шаблона."""
    context: Dict[str, Any] = {
        "request": request,
        "step": step,
        "csrf_token": get_csrf_token(request),
        "errors": [],
        "warnings": [],
    }
    context.update(extra)
    return context


def render_step(request: Request, step: int, **extra: Any) -> HTMLResponse:
    """Отрисовать шаг с полным набором данных."""
    return request.app.templates.TemplateResponse(
        request,
        STEP_TEMPLATES[step],
        base_context(request, step, **extra),
    )


# --------------------------------------------------------------------------- #
# Данные для шагов опроса
# --------------------------------------------------------------------------- #

async def step_context(request: Request, step: int, db: AsyncSession) -> Dict[str, Any]:
    """Собрать данные, необходимые конкретному шагу."""
    profile = get_profile_data(request)
    if step == 1:
        return {
            "system_types": ReferenceLoader.get_system_types(),
            "technologies": ReferenceLoader.get_technologies(),
            "system": profile.get("system") or {},
        }
    if step == 2:
        violator_types = ReferenceLoader.get_violator_types()
        return {
            "violator_types_external": {k: v for k, v in violator_types.items() if v.get("category") == "external"},
            "violator_types_internal": {k: v for k, v in violator_types.items() if v.get("category") == "internal"},
            "violator_type_names": {k: v["name"] for k, v in violator_types.items()},
            "violator_levels": ReferenceLoader.get_violator_levels(),
            "method_names": {code: item.get("name", "") for code, item in ReferenceLoader.get_methods().items()},
            "violators": profile.get("violators") or {},
        }
    if step == 3:
        return {
            "interfaces": ReferenceLoader.get_interfaces(),
            "selected_interfaces": profile.get("interfaces") or [],
        }
    if step == 4:
        objects = await get_all_objects(db)
        return {
            "objects": objects,
            "selected_objects": profile.get("selected_objects") or [],
            "technologies": ReferenceLoader.get_technologies(),
            "selected_technologies": (profile.get("system") or {}).get("technologies") or [],
            "impacts": ReferenceLoader.get_impacts(),
            "selected_impacts": profile.get("selected_impacts") or [],
        }
    return {}


# --------------------------------------------------------------------------- #
# Шаги опроса
# --------------------------------------------------------------------------- #

@router.get("/", response_class=HTMLResponse)
async def wizard_home(request: Request, db: AsyncSession = Depends(get_db)):
    """Стартовая страница wizard (шаг 1)."""
    return render_step(request, 1, **await step_context(request, 1, db))


@router.get("/step/{step_number}", response_class=HTMLResponse)
async def wizard_get_step(request: Request, step_number: int, db: AsyncSession = Depends(get_db)):
    """Показать шаг wizard (в том числе для навигации назад)."""
    if step_number not in STEP_TEMPLATES:
        raise HTTPException(status_code=404, detail="Шаг не найден")

    profile = get_profile_data(request)
    profile["current_step"] = step_number
    save_profile_data(request, profile)

    if step_number == 5:
        return await render_report(request, db)

    return render_step(request, step_number, **await step_context(request, step_number, db))


@router.post("/step1", response_class=HTMLResponse)
async def wizard_step1(request: Request, db: AsyncSession = Depends(get_db)):
    """Шаг 1: сведения о системе."""
    form_data = await request.form()
    check_csrf(request, form_data)

    security_level_raw = form_data.get("pd_security_level")
    security_level: Optional[int] = None
    if security_level_raw:
        try:
            security_level = int(str(security_level_raw))
        except ValueError:
            security_level = None

    system_profile = {
        "system_types": form_data.getlist("system_types"),
        "technologies": form_data.getlist("technologies"),
        "processes_pd": form_data.get("processes_pd") == "on",
        "pd_security_level": security_level,
        "has_internet_access": form_data.get("has_internet_access") == "on",
        "external_responsibility": (form_data.get("external_responsibility") or "").strip() or None,
    }

    from app.core.validator import validate_system_profile

    result = validate_system_profile(system_profile)
    if not result.is_valid:
        context = await step_context(request, 1, db)
        context.update(
            {
                "system": system_profile,
                "errors": result.errors,
                "warnings": result.warnings,
                "errors_step": 1,
            }
        )
        return request.app.templates.TemplateResponse(
            request, STEP_TEMPLATES[1], base_context(request, 1, **context), status_code=400
        )

    profile = get_profile_data(request)
    profile["system"] = system_profile
    profile["current_step"] = 2
    save_profile_data(request, profile)
    return RedirectResponse(url="/api/wizard/step/2", status_code=303)


@router.post("/step2", response_class=HTMLResponse)
async def wizard_step2(request: Request, db: AsyncSession = Depends(get_db)):
    """Шаг 2: нарушители."""
    form_data = await request.form()
    check_csrf(request, form_data)

    external_types = form_data.getlist("external_types")
    internal_types = form_data.getlist("internal_types")
    external_level, internal_level = compute_category_levels(external_types, internal_types)
    violator_profile = {
        "external_types": external_types,
        "external_level": external_level,
        "internal_types": internal_types,
        "internal_level": internal_level,
    }

    from app.core.validator import validate_violator_profile

    result = validate_violator_profile(violator_profile)
    if not result.is_valid:
        context = await step_context(request, 2, db)
        context.update(
            {
                "violators": violator_profile,
                "errors": result.errors,
                "warnings": result.warnings,
                "errors_step": 2,
            }
        )
        return request.app.templates.TemplateResponse(
            request, STEP_TEMPLATES[2], base_context(request, 2, **context), status_code=400
        )

    profile = get_profile_data(request)
    profile["violators"] = violator_profile
    profile["current_step"] = 3
    save_profile_data(request, profile)
    return RedirectResponse(url="/api/wizard/step/3", status_code=303)


@router.post("/step3", response_class=HTMLResponse)
async def wizard_step3(request: Request, db: AsyncSession = Depends(get_db)):
    """Шаг 3: интерфейсы."""
    form_data = await request.form()
    check_csrf(request, form_data)

    # Все типы интерфейсов считаются доступными по умолчанию: выбор убран
    interfaces = list(ReferenceLoader.get_interfaces())

    from app.core.validator import validate_interfaces

    result = validate_interfaces(interfaces)
    if not result.is_valid:
        context = await step_context(request, 3, db)
        context.update(
            {
                "selected_interfaces": interfaces,
                "errors": result.errors,
                "warnings": result.warnings,
                "errors_step": 3,
            }
        )
        return request.app.templates.TemplateResponse(
            request, STEP_TEMPLATES[3], base_context(request, 3, **context), status_code=400
        )

    profile = get_profile_data(request)
    profile["interfaces"] = interfaces
    profile["current_step"] = 4
    save_profile_data(request, profile)
    return RedirectResponse(url="/api/wizard/step/4", status_code=303)


@router.post("/step4", response_class=HTMLResponse)
async def wizard_step4(request: Request, db: AsyncSession = Depends(get_db)):
    """Шаг 4: объекты воздействия и виды воздействия."""
    form_data = await request.form()
    check_csrf(request, form_data)

    selected_objects = form_data.getlist("selected_objects")
    # Все виды воздействия применяются по умолчанию: выбор убран
    selected_impacts = list(ReferenceLoader.get_impacts())

    from app.core.validator import validate_step4

    result = validate_step4(selected_objects, selected_impacts)
    if not result.is_valid:
        context = await step_context(request, 4, db)
        context.update(
            {
                "selected_objects": selected_objects,
                "selected_impacts": selected_impacts,
                "errors": result.errors,
                "warnings": result.warnings,
                "errors_step": 4,
            }
        )
        return request.app.templates.TemplateResponse(
            request, STEP_TEMPLATES[4], base_context(request, 4, **context), status_code=400
        )

    profile = get_profile_data(request)
    profile["selected_objects"] = selected_objects
    profile["selected_impacts"] = selected_impacts
    profile["current_step"] = 5
    save_profile_data(request, profile)
    return RedirectResponse(url="/api/wizard/step/5", status_code=303)


# --------------------------------------------------------------------------- #
# Отчёт
# --------------------------------------------------------------------------- #

async def build_current_report(request: Request, db: AsyncSession, strict: bool = True):
    """Собрать профиль, отфильтровать УБИ и построить отчёт."""
    data = get_profile_data(request)
    if not data:
        if strict:
            raise HTTPException(status_code=400, detail="Профиль не заполнен. Пройдите шаги 1-4.")
        return None, None, None

    profile = build_profile(data)
    if strict:
        result = validate_user_profile(profile)
        if not result.is_valid:
            raise HTTPException(status_code=400, detail="; ".join(result.errors))
        # Шаг 5 читается из сессии; отчёт можно строить и при незаполненных шагах 2-3.
    threats = await get_all_threats(db)
    filtered = filter_threats(threats, profile)
    report = build_report(profile, filtered, len(threats), corpus=threats)
    return profile, threats, report


def report_context(profile: UserProfile, report) -> Dict[str, Any]:
    """Контекст страницы отчёта: правила, таблицы и предупреждения."""
    warnings: List[str] = []
    if not profile.selected_objects:
        warnings.append("Объекты воздействия не выбраны — перечень УБИ не ограничен по объектам.")
    if not profile.system.system_types:
        warnings.append("Типы ИС не выбраны — ограничение по негативным последствиям не применяется.")
    if not (profile.violators.external_types or profile.violators.internal_types):
        warnings.append("Виды нарушителей не выбраны — фильтр по нарушителям не применяется.")
    if not profile.interfaces:
        warnings.append("Интерфейсы не выбраны — ограничение по способам реализации не применяется.")

    rules_error = None
    rules = None
    tables: Dict[str, Any] = {}
    try:
        rules = load_rules()
        warnings.extend(rules.warnings)
        tables = build_tables(report, rules)
    except ReportRulesError as error:
        # Ошибку в report-rules.txt показываем прямо на странице отчёта
        rules_error = str(error)
        warnings.append(f"Правила отчёта не применены: {error}")

    return {
        "report": report,
        "user_profile": profile,
        "warnings": warnings,
        "rules": rules,
        "rules_error": rules_error,
        "tables": tables,
        "report_title": rules.title if rules else "Модель угроз безопасности информации",
        "show_profile": rules.show_profile if rules else True,
    }


async def render_report(request: Request, db: AsyncSession) -> HTMLResponse:
    """Отрисовать шаг 5 с предпросмотром отчёта."""
    profile = build_profile(get_profile_data(request))
    threats = await get_all_threats(db)
    filtered = filter_threats(threats, profile)
    report = build_report(profile, filtered, len(threats), corpus=threats)

    return request.app.templates.TemplateResponse(
        request,
        STEP_TEMPLATES[5],
        base_context(request, 5, **report_context(profile, report)),
    )


@router.post("/clear")
async def wizard_clear(request: Request):
    """Очистить все введённые данные (сессия и cookie) и вернуться к шагу 1."""
    request.session.clear()
    response = RedirectResponse(url="/api/wizard/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response
