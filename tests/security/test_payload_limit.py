"""Tests for payload size limits and anti-DoS middleware."""

import pytest
from httpx import ASGITransport, AsyncClient
from app.core.config import settings
from app.main import app


@pytest.mark.anyio
async def test_payload_limit_rejection():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Construct a payload larger than MAX_PAYLOAD_BYTES
        large_body = "x" * (settings.MAX_PAYLOAD_BYTES + 500)

        # Make request with body exceeding Content-Length
        response = await client.post(
            "/api/v1/analyze",
            content=f'{{"prompt": "{large_body}"}}',
            headers={"Content-Type": "application/json"},
        )

        assert response.status_code == 413
        data = response.json()
        assert "Payload too large" in data["detail"]


@pytest.mark.anyio
async def test_normal_payload_accepted():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/v1/analyze",
            json={"prompt": "Este é um teste com payload de tamanho normal."},
        )

        assert response.status_code == 200

