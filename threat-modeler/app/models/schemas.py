"""Pydantic-схемы профиля системы и строк отчёта."""

from typing import List, Optional

from pydantic import BaseModel, Field


class SystemProfile(BaseModel):
    """Профиль информационной системы (шаг 1)."""

    system_types: List[str] = Field(default_factory=list, description="Типы ИС (АСУ ТП, ГИС, ПДн и т. д.)")
    technologies: List[str] = Field(default_factory=list, description="Технологические признаки системы")
    processes_pd: bool = Field(default=False, description="Обрабатываются персональные данные")
    pd_security_level: Optional[int] = Field(default=None, ge=1, le=4, description="Уровень защищённости ПДн (1-4)")
    has_internet_access: bool = Field(default=False, description="Есть доступ в Интернет")
    external_responsibility: Optional[str] = Field(default=None, description="Организация с внешней ответственностью")


class ViolatorProfile(BaseModel):
    """Профиль нарушителей (шаг 2)."""

    external_types: List[str] = Field(default_factory=list, description="Виды внешних нарушителей")
    external_level: Optional[str] = Field(default=None, description="Уровень возможностей внешних нарушителей (Н1-Н4)")
    internal_types: List[str] = Field(default_factory=list, description="Виды внутренних нарушителей")
    internal_level: Optional[str] = Field(default=None, description="Уровень возможностей внутренних нарушителей (Н1-Н4)")


class UserProfile(BaseModel):
    """Полный профиль (состояние wizard)."""

    system: SystemProfile = Field(default_factory=SystemProfile)
    violators: ViolatorProfile = Field(default_factory=ViolatorProfile)
    interfaces: List[str] = Field(default_factory=list, description="Выбранные типы интерфейсов")
    selected_objects: List[str] = Field(default_factory=list, description="Выбранные объекты воздействия")
    selected_impacts: List[str] = Field(default_factory=list, description="Выбранные виды воздействия (В1-В7)")
    current_step: int = Field(default=1, ge=1, le=5, description="Текущий шаг wizard")


class ConsequenceView(BaseModel):
    """Строка таблицы 1 отчёта (виды риска и последствия)."""

    code: str
    risk: str
    risk_name: str
    name: str
    conditions: str


class ThreatView(BaseModel):
    """Строка таблицы 2 отчёта (перечень УБИ)."""

    ubi_id: str = Field(description="Идентификатор УБИ")
    ubi_name: str = Field(description="Наименование УБИ")
    violator_internal: str = Field(default="", description="Уровень возможностей внутреннего нарушителя")
    violator_external: str = Field(default="", description="Уровень возможностей внешнего нарушителя")
    objects: str = Field(default="", description="Объекты воздействия")
    methods: str = Field(default="", description="Способы реализации")
    impacts: str = Field(default="", description="Виды воздействия")
    consequences: str = Field(default="", description="Негативные последствия")
    tactics: str = Field(default="", description="Тактики")
    techniques: str = Field(default="", description="Техники")
    notes: str = Field(default="", description="Примечания")


class ReportPreview(BaseModel):
    """Результат корреляции: таблица 1 + таблица 2 + сводка."""

    profile: UserProfile
    risk_table: List[ConsequenceView] = Field(default_factory=list)
    threats: List[ThreatView] = Field(default_factory=list)
    total_threats: int = 0
    total_corpus: int = 0
    statistics: dict = Field(default_factory=dict)
