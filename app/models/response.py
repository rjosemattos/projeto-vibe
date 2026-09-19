"""Response models for Prompt Sanitizer API."""

from enum import Enum
from typing import List
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    """Classification levels for sensitivity and privacy risk."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionItem(BaseModel):
    """Summary of a detected sensitive data entity.

    NOTE: The raw sensitive string is NEVER exposed in this model to adhere to Privacy by Design.
    """

    type: str = Field(
        ...,
        description="Type of sensitive entity (e.g., CPF, EMAIL, API_KEY).",
        examples=["CPF"],
    )
    severity: SeverityLevel = Field(
        ...,
        description="Severity classification of the detected entity.",
        examples=[SeverityLevel.HIGH],
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score of the detection algorithm.",
        examples=[0.99],
    )
    strategy: str = Field(
        ...,
        description="Strategy or algorithm utilized for identification and validation.",
        examples=["regex_semantic_mod11"],
    )
    masked_value: str = Field(
        ...,
        description="Safely masked indicator for UI review (no raw sensitive data).",
        examples=["123.***.***-09"],
    )


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


class PromptAnalyzeResponse(BaseModel):
    """Complete analysis and sanitization response payload."""

    has_sensitive_data: bool = Field(
        ...,
        description="True if any sensitive information was identified.",
        examples=[True],
    )
    risk_level: SeverityLevel = Field(
        ...,
        description="Overall aggregated risk level.",
        examples=[SeverityLevel.HIGH],
    )
    total_detections: int = Field(
        ...,
        description="Total count of sensitive entities identified in the prompt.",
        examples=[1],
    )
    detections: List[DetectionItem] = Field(
        default_factory=list,
        description="List of detected sensitive items with safe masked values.",
    )
    sanitized_prompt: str = Field(
        ...,
        description="Sanitized version of prompt with entity-consistent placeholders.",
        examples=["Analise este cliente: João da Silva, CPF [CPF_USUARIO_1], e me diga se ele pode contratar o serviço."],
    )
    risk_report: RiskReport = Field(
        ...,
        description="Detailed risk evaluation and contributing factors.",
    )

