"""Tests for Supabase / Google OAuth JWT authentication, institutional domain restrictions, and tenant isolation."""

import time
import jwt
import pytest
from httpx import ASGITransport, AsyncClient

from app.core.config import settings
from app.main import app

JWT_SECRET = "super-secret-jwt-key-for-supabase-testing-12345678"


def generate_supabase_token(sub: str, email: str, secret: str = JWT_SECRET, expired: bool = False) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "email": email,
        "aud": "authenticated",
        "role": "authenticated",
        "iat": now,
        "exp": now - 3600 if expired else now + 3600,
        "app_metadata": {"provider": "google"},
    }
    return jwt.encode(payload, secret, algorithm="HS256")


@pytest.fixture
def supabase_env(monkeypatch):
    monkeypatch.setattr(settings, "SUPABASE_URL", "https://xyzcompany.supabase.co")
    monkeypatch.setattr(settings, "SUPABASE_ANON_KEY", "anon-key-mock-12345")
    monkeypatch.setattr(settings, "SUPABASE_JWT_SECRET", JWT_SECRET)
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "ALLOWED_EMAIL_DOMAINS", ["cesar.school"])


@pytest.mark.anyio
async def test_auth_config_endpoint(supabase_env):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        res = await c.get("/api/v1/auth/config")
        assert res.status_code == 200
        data = res.json()
        assert data["supabase_enabled"] is True
        assert data["supabase_url"] == "https://xyzcompany.supabase.co"
        assert data["supabase_anon_key"] == "anon-key-mock-12345"
        assert data["allowed_domains"] == ["cesar.school"]
        assert "JWT_SECRET" not in str(data)


@pytest.mark.anyio
async def test_supabase_jwt_authenticates_cesar_school_user(supabase_env):
    token = generate_supabase_token("user-cesar-123", "carlos.silva@cesar.school")
    headers = {"Authorization": f"Bearer {token}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        res = await c.get("/api/v1/auth/me", headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["authenticated"] is True
        assert data["username"] == "carlos.silva@cesar.school"
        assert data["user_id"] == "user-cesar-123"


@pytest.mark.anyio
async def test_supabase_jwt_rejects_non_cesar_domain(supabase_env):
    # Even if Google issues a token, non-cesar.school domains must be blocked by the backend
    token_gmail = generate_supabase_token("user-gmail", "alguem@gmail.com")
    token_external = generate_supabase_token("user-external", "hacker@empresa-externa.com")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        res1 = await c.get("/api/v1/rules", headers={"Authorization": f"Bearer {token_gmail}"})
        assert res1.status_code == 401

        res2 = await c.get("/api/v1/rules", headers={"Authorization": f"Bearer {token_external}"})
        assert res2.status_code == 401


@pytest.mark.anyio
async def test_supabase_jwt_crud_and_isolation(supabase_env):
    token_alice = generate_supabase_token("alice-uuid-001", "alice@cesar.school")
    token_bob = generate_supabase_token("bob-uuid-002", "bob@cesar.school")

    headers_alice = {"Authorization": f"Bearer {token_alice}"}
    headers_bob = {"Authorization": f"Bearer {token_bob}"}

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        # Alice creates a confidential rule
        create_res = await c.post(
            "/api/v1/rules",
            headers=headers_alice,
            json={"term": "ProjetoSecreto", "replacement_tag": "[PROJECT_X]"},
        )
        assert create_res.status_code == 201

        # Alice analyzes a prompt: rule must be applied
        analysis_alice = await c.post(
            "/api/v1/analyze",
            headers=headers_alice,
            json={"prompt": "Revise o ProjetoSecreto da empresa"},
        )
        assert analysis_alice.status_code == 200
        assert analysis_alice.json()["sanitized_prompt"] == "Revise o [PROJECT_X] da empresa"

        # Bob lists rules: must be empty (isolated)
        rules_bob = await c.get("/api/v1/rules", headers=headers_bob)
        assert rules_bob.status_code == 200
        assert rules_bob.json() == []


@pytest.mark.anyio
async def test_expired_or_invalid_jwt_rejected(supabase_env):
    expired_token = generate_supabase_token("user-old", "old@cesar.school", expired=True)
    bad_signature_token = generate_supabase_token("user-hacker", "hacker@cesar.school", secret="wrong-secret-key-123")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        assert (await c.get("/api/v1/rules", headers={"Authorization": f"Bearer {expired_token}"})).status_code == 401
        assert (await c.get("/api/v1/rules", headers={"Authorization": f"Bearer {bad_signature_token}"})).status_code == 401


@pytest.mark.anyio
async def test_supabase_es256_jwks_jwt_verified_even_with_hmac_secret(supabase_env, monkeypatch):
    """Supabase projects using asymmetric ES256 keys must work even if SUPABASE_JWT_SECRET is an HMAC string."""
    import json
    from cryptography.hazmat.primitives.asymmetric import ec
    from jwt import PyJWKSet
    from jwt.algorithms import ECAlgorithm
    import app.auth.supabase_jwt as sb_jwt

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(ECAlgorithm.to_jwk(private_key.public_key()))
    public_jwk["kid"] = "supabase-es256-kid-1"
    public_jwk["alg"] = "ES256"
    public_jwk["use"] = "sig"
    jwk_set = PyJWKSet.from_dict({"keys": [public_jwk]})

    monkeypatch.setattr(sb_jwt, "_fetch_jwks", lambda _url: jwk_set)

    now = int(time.time())
    es256_token = jwt.encode(
        {
            "sub": "es256-user-999",
            "email": "estudante@cesar.school",
            "aud": "authenticated",
            "role": "authenticated",
            "iat": now,
            "exp": now + 3600,
        },
        private_key,
        algorithm="ES256",
        headers={"kid": "supabase-es256-kid-1"},
    )

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        res_me = await c.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {es256_token}"})
        assert res_me.status_code == 200
        assert res_me.json()["authenticated"] is True
        assert res_me.json()["username"] == "estudante@cesar.school"

        res_rules = await c.get("/api/v1/rules", headers={"Authorization": f"Bearer {es256_token}"})
        assert res_rules.status_code == 200

