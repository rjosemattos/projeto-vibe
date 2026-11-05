"""Integration tests for the confidential rules CRUD endpoints."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

HEADERS = {"X-User-Id": "crud-test-user"}


@pytest.mark.anyio
async def test_rules_crud_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        created = await client.post(
            "/api/v1/rules",
            json={"term": "ProjetoVibe", "replacement_tag": "[SECRET]"},
            headers=HEADERS,
        )
        assert created.status_code == 201
        body = created.json()
        assert "ProjetoVibe" not in created.text
        rule_id = body["id"]

        dup = await client.post(
            "/api/v1/rules",
            json={"term": "projetovibe", "replacement_tag": "[SECRET]"},
            headers=HEADERS,
        )
        assert dup.status_code == 409

        analyzed = await client.post(
            "/api/v1/analyze", json={"prompt": "Falar sobre ProjetoVibe"}, headers=HEADERS
        )
        assert analyzed.json()["sanitized_prompt"] == "Falar sobre [SECRET]"

        updated = await client.put(
            f"/api/v1/rules/{rule_id}", json={"replacement_tag": "[NOVO]"}, headers=HEADERS
        )
        assert updated.status_code == 200
        assert updated.json()["replacement_tag"] == "[NOVO]"

        other_tenant = await client.get("/api/v1/rules", headers={"X-User-Id": "someone-else"})
        assert other_tenant.json() == []

        assert (await client.delete(f"/api/v1/rules/{rule_id}", headers=HEADERS)).status_code == 204
        assert (await client.delete(f"/api/v1/rules/{rule_id}", headers=HEADERS)).status_code == 404
