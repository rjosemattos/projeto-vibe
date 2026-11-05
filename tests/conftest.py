"""Pytest fixtures and configuration."""

import os
import tempfile

# Isolate tests from the real user data directory (keys, rules store) BEFORE importing the app.
os.environ.setdefault("PROMPT_SANITIZER_DATA_DIR", tempfile.mkdtemp(prefix="prompt-sanitizer-tests-"))

import pytest
from httpx import ASGITransport, AsyncClient
from app.detection.engine import DetectionEngine
from app.main import app
from app.risk.analyzer import RiskAnalyzer
from app.sanitization.engine import SanitizationEngine


@pytest.fixture
def detection_engine():
    """Provides a fresh DetectionEngine instance."""
    return DetectionEngine()


@pytest.fixture
def risk_analyzer():
    """Provides a fresh RiskAnalyzer instance."""
    return RiskAnalyzer()


@pytest.fixture
def sanitization_engine():
    """Provides a fresh SanitizationEngine instance."""
    return SanitizationEngine()


@pytest.fixture
async def async_client():
    """Provides an async HTTP test client for the FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

