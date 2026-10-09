"""SQLAlchemy модели базы данных.

Схема соответствует каноническим справочникам, собранным
``scripts/import_sources.py`` из источников рабочего каталога:

* 38 объектов воздействия (``объекты.txt`` / ``бдму.xlsx``);
* 9 способов реализации СП1-СП9 (``способы реализации.txt``);
* 7 видов воздействия В1-В7 (``виды воздействия.txt``);
* виды риска У1-У3 и 67 негативных последствий уX.Y
  (``ИС и негативные последствия.xlsx`` + ``негативные последствия.txt``);
* 13 типов информационных систем (``информационные системы.txt``);
* 13 видов нарушителей (с уровнем возможностей Н1-Н4 и способами СП1-СП9)
  и 4 уровня возможностей;
* тактики Т1-Т10 и 144 техники;
* 10 типов интерфейсов с выведенным перечнем способов реализации;
* 227 УБИ и 506 связей «УБИ x объект» с индивидуальным набором
  способов реализации, последствий, тактик и техник.

В базе хранятся только справочные данные и корпус УБИ. Данные опроса
пользователя и результаты отчёта в БД не записываются: они живут только в
cookie-сессии браузера и передаются в файл по явной команде экспорта.
"""

from typing import List

from sqlalchemy import Column, ForeignKey, Integer, String, Table, Text
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    """Базовый класс моделей."""

    pass


# Соответствие «негативное последствие -> применимый тип ИС»
consequence_system_types = Table(
    "consequence_system_types",
    Base.metadata,
    Column("consequence_code", String, ForeignKey("consequences.code"), primary_key=True),
    Column("system_type_code", String, ForeignKey("system_types.code"), primary_key=True),
)


class Object(Base):
    """Объект воздействия (О1-О38)."""

    __tablename__ = "objects"

    code = Column(String, primary_key=True, index=True)
    num = Column(Integer, nullable=False, index=True)
    name = Column(Text, nullable=False)
    technologies = Column(Text, default="")  # CSV технологических признаков


class Method(Base):
    """Способ реализации угрозы (СП1-СП9)."""

    __tablename__ = "methods"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)


class Impact(Base):
    """Вид воздействия (В1-В7)."""

    __tablename__ = "impacts"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)


class Tactic(Base):
    """Тактика реализации угрозы (Т1-Т10)."""

    __tablename__ = "tactics"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)

    techniques = relationship("Technique", back_populates="tactic", order_by="Technique.code")


class Technique(Base):
    """Техника реализации угрозы (например, Т2.5)."""

    __tablename__ = "techniques"

    code = Column(String, primary_key=True, index=True)
    tactic_code = Column(String, ForeignKey("tactics.code"), nullable=False, index=True)
    name = Column(Text, nullable=False)
    description = Column(Text, default="")

    tactic = relationship("Tactic", back_populates="techniques")


class SystemType(Base):
    """Тип информационной системы (АСУ ТП, ГИС, ПДн и т. д.)."""

    __tablename__ = "system_types"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    description = Column(Text, default="")


class RiskType(Base):
    """Вид риска (ущерба): У1, У2, У3."""

    __tablename__ = "risk_types"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)


class Consequence(Base):
    """Негативное последствие (у1.1 ... у3.30)."""

    __tablename__ = "consequences"

    code = Column(String, primary_key=True, index=True)
    risk_code = Column(String, ForeignKey("risk_types.code"), nullable=False, index=True)
    name = Column(Text, nullable=False)
    conditions = Column(Text, default="")

    risk = relationship("RiskType")
    system_types = relationship(
        "SystemType", secondary=consequence_system_types, lazy="selectin", order_by="SystemType.code"
    )


class ViolatorLevel(Base):
    """Уровень возможностей нарушителя (Н1-Н4)."""

    __tablename__ = "violator_levels"

    code = Column(String, primary_key=True, index=True)
    rank = Column(Integer, nullable=False)
    name = Column(Text, nullable=False)
    description = Column(Text, default="")
    violators = Column(Text, default="")
    methods = Column(Text, default="")             # CSV кодов способов реализации (СП1-СП9)


class ViolatorType(Base):
    """Вид нарушителя (13 позиций)."""

    __tablename__ = "violator_types"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    category = Column(String, nullable=False, index=True)  # external | internal
    level = Column(String, default="", index=True)         # уровень возможностей Н1-Н4
    methods = Column(Text, default="")                     # CSV способов реализации (СП1-СП9)
    goals = Column(Text, default="")


class Interface(Base):
    """Тип интерфейса объекта воздействия."""

    __tablename__ = "interfaces"

    code = Column(String, primary_key=True, index=True)
    name = Column(Text, nullable=False)
    description = Column(Text, default="")
    methods = Column(Text, default="")  # CSV способов реализации СП*, доступных через интерфейс
    source = Column(Text, default="")   # источник вывода соответствия


class Threat(Base):
    """Угроза безопасности информации (УБИ)."""

    __tablename__ = "threats"

    id = Column(String, primary_key=True, index=True)          # УБИ.001
    name = Column(Text, nullable=False)
    source_note = Column(Text, default="")                     # источник угрозы из УБИ-объект.docx
    note = Column(Text, default="")                            # примечание из сводной таблицы
    violator_int = Column(Text, default="")                    # CSV уровней внутреннего нарушителя
    violator_ext = Column(Text, default="")                    # CSV уровней внешнего нарушителя

    pairs = relationship(
        "ThreatObject",
        back_populates="threat",
        cascade="all, delete-orphan",
        order_by="ThreatObject.object_code",
        lazy="selectin",
    )


class ThreatObject(Base):
    """Связь «УБИ x объект воздействия» с индивидуальной корреляцией из бдму.xlsx."""

    __tablename__ = "threat_objects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_id = Column(String, ForeignKey("threats.id"), nullable=False, index=True)
    object_code = Column(String, ForeignKey("objects.code"), nullable=False, index=True)
    methods = Column(Text, default="")        # CSV СП*
    consequences = Column(Text, default="")   # CSV уX.Y
    tactics = Column(Text, default="")        # CSV Т*
    techniques = Column(Text, default="")     # CSV Т*.*

    threat = relationship("Threat", back_populates="pairs")
    object = relationship("Object", lazy="joined")

    # ------------------------------------------------------------------ #
    # Удобные представления CSV-полей
    # ------------------------------------------------------------------ #

    @staticmethod
    def _split(value: str) -> List[str]:
        return [item for item in (value or "").split(",") if item]

    @property
    def method_codes(self) -> List[str]:
        return self._split(self.methods)

    @property
    def consequence_codes(self) -> List[str]:
        return self._split(self.consequences)

    @property
    def tactic_codes(self) -> List[str]:
        return self._split(self.tactics)

    @property
    def technique_codes(self) -> List[str]:
        return self._split(self.techniques)


# ---------------------------------------------------------------------- #
# Вспомогательные функции для работы с CSV-полями моделей
# ---------------------------------------------------------------------- #

def split_csv(value: str) -> List[str]:
    """Разобрать CSV-поле модели в список кодов."""
    return [item for item in (value or "").split(",") if item]


def join_csv(values: List[str]) -> str:
    """Собрать список кодов в CSV-поле модели."""
    seen: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
    return ",".join(seen)


__all__ = [
    "Base",
    "Consequence",
    "Impact",
    "Interface",
    "Method",
    "Object",
    "RiskType",
    "SystemType",
    "Tactic",
    "Technique",
    "Threat",
    "ThreatObject",
    "ViolatorLevel",
    "ViolatorType",
    "consequence_system_types",
    "join_csv",
    "split_csv",
]
