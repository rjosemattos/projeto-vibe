"""Shared result models (severity levels and risk report)."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Classification levels for sensitivity and privacy risk."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RiskReport(BaseModel):
    """Detailed risk assessment metrics and transparent reasoning."""

    risk_level: SeverityLevel = Field(
        ...,
        description="Overall prompt risk level.",
        examples=[SeverityLevel.HIGH],
    )
    score: int = Field(
        ...,
        ge=0,
        le=100,
        description="Calculated composite risk score from 0 (safe) to 100 (critical).",
        examples=[75],
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Human-readable reasons and factors contributing to the risk score.",
        examples=["Presença de identificador governamental (CPF)."],
    )
