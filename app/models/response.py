"""Modelos de resultado compartilhados (níveis de severidade e relatório de risco)."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Níveis de classificação de sensibilidade e de risco à privacidade."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskReport(BaseModel):
    """Métricas detalhadas da avaliação de risco e os motivos que levaram a ela."""

    risk_level: SeverityLevel = Field(
        ...,
        description="Nível de risco geral do prompt.",
        examples=[SeverityLevel.HIGH],
    )
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Pontuação de risco calculada, de 0 (seguro) a 100 (crítico).",
        examples=[75],
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Motivos legíveis que explicam a pontuação de risco.",
        examples=["Presença de identificador governamental (CPF)."],
    )
