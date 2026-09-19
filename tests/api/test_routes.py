"""Integration tests for FastAPI endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.anyio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "app" in data


@pytest.mark.anyio
async def test_analyze_endpoint_with_sensitive_data():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        prompt = "Analise o cliente João da Silva, CPF 123.456.789-09, email teste@empresa.com"
        response = await client.post("/api/v1/analyze", json={"prompt": prompt})

        assert response.status_code == 200
        data = response.json()

        assert data["has_sensitive_data"] is True
        assert data["risk_level"] in ("HIGH", "CRITICAL")
        assert data["total_detections"] == 2
        assert "[CPF_USUARIO]" in data["sanitized_prompt"]
        assert "[EMAIL_USUARIO]" in data["sanitized_prompt"]

        # Critical privacy check: RAW CPF and RAW Email must not appear in detections list
        for item in data["detections"]:
            assert "123.456.789-09" not in item["masked_value"]
            assert "teste@empresa.com" not in item["masked_value"]

        # Privacy security headers check
        assert response.headers.get("x-content-type-options") == "nosniff"
        assert response.headers.get("x-frame-options") == "DENY"
        assert "no-store" in response.headers.get("cache-control", "")


@pytest.mark.anyio
async def test_analyze_endpoint_clean_prompt():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        prompt = "Escreva um poema sobre privacidade e segurança da informação."
        response = await client.post("/api/v1/analyze", json={"prompt": prompt})

        assert response.status_code == 200
        data = response.json()
        assert data["has_sensitive_data"] is False
        assert data["risk_level"] == "LOW"
        assert data["total_detections"] == 0
        assert data["sanitized_prompt"] == prompt


@pytest.mark.anyio
async def test_analyze_endpoint_critical_secrets():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        prompt = 'Deploy config: OPENAI_API_KEY="sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"'
        response = await client.post("/api/v1/analyze", json={"prompt": prompt})

        assert response.status_code == 200
        data = response.json()
        assert data["has_sensitive_data"] is True
        assert data["risk_level"] == "CRITICAL"
        assert "sk-proj-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6" not in str(data)

