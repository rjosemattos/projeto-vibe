"""Fixtures e configuração do pytest."""

import os
import tempfile

# Isola os testes da pasta de dados real do usuário (chaves, cofre de regras) ANTES de importar a aplicação.
os.environ.setdefault("PROMPT_SANITIZER_DATA_DIR", tempfile.mkdtemp(prefix="prompt-sanitizer-tests-"))

import pytest
from app.detection.engine import DetectionEngine
from app.risk.analyzer import RiskAnalyzer
from app.sanitization.engine import SanitizationEngine


@pytest.fixture
def detection_engine():
    """Fornece uma instância nova do DetectionEngine."""
    return DetectionEngine()


@pytest.fixture
def risk_analyzer():
    """Fornece uma instância nova do RiskAnalyzer."""
    return RiskAnalyzer()


@pytest.fixture
def sanitization_engine():
    """Fornece uma instância nova do SanitizationEngine."""
    return SanitizationEngine()

