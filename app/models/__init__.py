"""Modelos de dados compartilhados pelo motor de detecção e pelo agente desktop."""

from app.models.response import RiskReport, SeverityLevel
from app.models.rules import (
    ConfidentialRuleRecord,
    RuleCreateRequest,
    RuleResponse,
    RuleUpdateRequest,
)

__all__ = [
    "RiskReport",
    "SeverityLevel",
    "RuleCreateRequest",
    "RuleUpdateRequest",
    "RuleResponse",
    "ConfidentialRuleRecord",
]
