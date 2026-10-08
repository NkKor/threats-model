"""Настройки приложения."""

from typing import List, Union

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Настройки приложения (читаются из переменных окружения и .env)."""

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=False, extra="ignore")

    app_name: str = Field(default="Threat Modeler FSTEC", description="Имя приложения")
    app_port: int = Field(default=8080, description="Порт для запуска")
    env: str = Field(default="development", description="Окружение: development, production, testing")

    # База данных
    db_path: str = Field(default="./data/threats.db", description="Путь к SQLite БД")

    # Каталоги
    data_dir: str = Field(default="./data", description="Директория данных")
    reports_dir: str = Field(default="./reports", description="Директория отчётов")

    # Сессии: данные опроса живут только в cookie браузера.
    # session_max_age = 0 — cookie сессии (удаляется при закрытии браузера).
    session_secret: str = Field(
        default="dev-insecure-session-secret-change-me",
        description="Ключ подписи cookie-сессии; в production задаётся переменной SESSION_SECRET",
    )
    session_max_age: int = Field(
        default=0, description="Время жизни сессии в секундах; 0 — до закрытия браузера"
    )

    # CORS: по умолчанию пусто (same-origin), список задаётся через CORS_ORIGINS.
    # Тип Union[str, List[str]] — иначе pydantic-settings трактует значение из
    # .env как JSON (пустая строка в CORS_ORIGINS= приводила бы к ошибке чтения).
    cors_origins: Union[str, List[str]] = Field(
        default_factory=list, description="Разрешённые источники для CORS"
    )

    # Пересоздавать БД из seed при старте, если она пуста
    seed_on_startup: bool = Field(default=True, description="Загружать seed-данные при пустой БД")

    # Логирование SQL (по умолчанию выключено, включается DB_ECHO=true)
    db_echo: bool = Field(default=False, description="Выводить SQL-запросы в лог")

    # --- Трактовка правил корреляции (см. app/core/correlation.py) ---------- #
    # R3: «capability» — нарушитель реализует угрозы своего уровня и ниже (по умолчанию);
    #     «strict» — уровень нарушителя должен быть явно указан у угрозы.
    level_semantics: str = Field(default="capability", description="Трактовка уровней нарушителей: capability | strict")

    # R5: поведение для УБИ, у которых виды воздействия не определены таблицей 3
    #     «keep» — не ограничивать (по умолчанию); «exclude» — исключать.
    impacts_semantics: str = Field(default="keep", description="Поведение при неопределённых видах воздействия: keep | exclude")

    @field_validator("level_semantics", "impacts_semantics")
    @classmethod
    def _validate_mode(cls, value: str, info):
        """Проверить допустимые значения режимов."""
        allowed = {
            "level_semantics": {"capability", "strict"},
            "impacts_semantics": {"keep", "exclude"},
        }[info.field_name]
        value = (value or "").strip().lower()
        if value not in allowed:
            raise ValueError(f"{info.field_name}: допустимые значения {sorted(allowed)}")
        return value

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value):
        """Поддержать как список, так и строку с разделителями."""
        if value is None or value == "":
            return []
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.env.lower() in ("production", "prod")


settings = Settings()
