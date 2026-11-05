"""Tests for hosted mode: login, sessions, CSRF, lockout, tenant isolation and rate limits."""

import pytest
from httpx import ASGITransport, AsyncClient

from app.auth import service
from app.auth.routes import rate_limiter
from app.auth.store import _stores
from app.core.config import settings
from app.main import app

PASSWORD = "correct-horse-battery"


@pytest.fixture
def hosted(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "AUTH_ENABLED", True)
    monkeypatch.setattr(settings, "COOKIE_SECURE", False)  # httpx test client speaks plain http
    monkeypatch.setattr(settings, "DB_PATH", str(tmp_path / "test.db"))
    rate_limiter.reset()
    service.create_user("alice", PASSWORD)
    service.create_user("bob", PASSWORD)
    yield
    for store in _stores.values():
        store.close()
    _stores.clear()


def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def login(c, user="alice", password=PASSWORD):
    return await c.post("/api/v1/auth/login", json={"username": user, "password": password})


@pytest.mark.anyio
async def test_unauthenticated_requests_are_rejected(hosted):
    async with client() as c:
        assert (await c.get("/api/v1/rules")).status_code == 401
        assert (await c.post("/api/v1/analyze", json={"prompt": "x"})).status_code == 401
        # The old spoofable header must not grant access
        assert (await c.get("/api/v1/rules", headers={"X-User-Id": "alice"})).status_code == 401
        assert (await c.get("/health")).status_code == 200


@pytest.mark.anyio
async def test_login_sets_hardened_cookie_and_generic_errors(hosted):
    async with client() as c:
        ok = await login(c)
        assert ok.status_code == 200
        cookie = ok.headers["set-cookie"].lower()
        assert "httponly" in cookie and "samesite=strict" in cookie
        bad_user = await login(c, "nobody", "whatever-password")
        bad_pass = await login(c, "alice", "wrong-password-here")
        assert bad_user.json() == bad_pass.json()  # no username enumeration


@pytest.mark.anyio
async def test_csrf_required_for_state_changes(hosted):
    async with client() as c:
        csrf = (await login(c)).json()["csrf_token"]
        body = {"term": "Segredo", "replacement_tag": "[SEG]"}
        assert (await c.post("/api/v1/rules", json=body)).status_code == 403
        assert (await c.post("/api/v1/rules", json=body, headers={"X-CSRF-Token": "bad"})).status_code == 403
        ok = await c.post("/api/v1/rules", json=body, headers={"X-CSRF-Token": csrf})
        assert ok.status_code == 201
        cross = await c.post(
            "/api/v1/rules", json={**body, "term": "Outro"},
            headers={"X-CSRF-Token": csrf, "Origin": "http://evil.example"},
        )
        assert cross.status_code == 403


@pytest.mark.anyio
async def test_tenant_isolation_and_per_user_keys(hosted):
    async with client() as a, client() as b:
        csrf_a = (await login(a, "alice")).json()["csrf_token"]
        csrf_b = (await login(b, "bob")).json()["csrf_token"]
        created = await a.post(
            "/api/v1/rules", json={"term": "Confidencial", "replacement_tag": "[XX]"},
            headers={"X-CSRF-Token": csrf_a},
        )
        rule_id = created.json()["id"]
        assert (await b.get("/api/v1/rules")).json() == []
        assert (await b.get(f"/api/v1/rules/{rule_id}")).status_code == 404
        assert (await b.delete(f"/api/v1/rules/{rule_id}", headers={"X-CSRF-Token": csrf_b})).status_code == 404
        # Same term for Bob is not a duplicate and is applied only to Bob
        assert (await b.post(
            "/api/v1/rules", json={"term": "Confidencial", "replacement_tag": "[YY]"},
            headers={"X-CSRF-Token": csrf_b},
        )).status_code == 201
        out = await a.post("/api/v1/analyze", json={"prompt": "dado Confidencial"}, headers={"X-CSRF-Token": csrf_a})
        assert out.json()["sanitized_prompt"] == "dado [XX]"


@pytest.mark.anyio
async def test_logout_invalidates_session(hosted):
    async with client() as c:
        csrf = (await login(c)).json()["csrf_token"]
        assert (await c.post("/api/v1/auth/logout", headers={"X-CSRF-Token": csrf})).status_code == 204
        assert (await c.get("/api/v1/rules")).status_code == 401


@pytest.mark.anyio
async def test_account_lockout_after_repeated_failures(hosted, monkeypatch):
    monkeypatch.setattr(settings, "RATE_LIMIT_LOGIN_PER_MIN", 1000)
    async with client() as c:
        for _ in range(settings.MAX_FAILED_LOGINS):
            assert (await login(c, "alice", "wrong-password-here")).status_code == 401
        locked = await login(c, "alice", PASSWORD)
        assert locked.status_code == 401  # even the right password is refused while locked


@pytest.mark.anyio
async def test_login_rate_limit(hosted, monkeypatch):
    monkeypatch.setattr(settings, "MAX_FAILED_LOGINS", 1000)
    async with client() as c:
        codes = [(await login(c, "ghost", "wrong-password-here")).status_code for _ in range(settings.RATE_LIMIT_LOGIN_PER_MIN + 2)]
        assert codes[-1] == 429


@pytest.mark.anyio
async def test_idle_session_expires(hosted, monkeypatch):
    async with client() as c:
        await login(c)
        monkeypatch.setattr(settings, "SESSION_IDLE_MINUTES", -1)
        assert (await c.get("/api/v1/rules")).status_code == 401


def test_password_policy():
    for bad in ("short", "alicealicealice", "aaaaaaaaaaaaaaaa", "password"):
        with pytest.raises(ValueError):
            service.validate_password_strength(bad, "alice")
    service.validate_password_strength(PASSWORD, "alice")
