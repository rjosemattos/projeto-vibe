"""Guards for the static UI: CSP-compatible markup and no emoji used as iconography."""

import re
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app

STATIC = Path(__file__).resolve().parents[2] / "app" / "static"
EMOJI = re.compile("[\U0001F300-\U0001FAFF\u2600-\u27BF\uFE0F]")


@pytest.mark.parametrize("name", ["index.html", "login.html", "app.js", "login.js", "style.css"])
def test_no_emoji_in_ui(name):
    assert not EMOJI.search((STATIC / name).read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", ["index.html", "login.html"])
def test_markup_is_csp_compatible(name):
    html = (STATIC / name).read_text(encoding="utf-8")
    assert not re.search(r"\sstyle=", html), "inline style attributes violate style-src 'self'"
    assert not re.search(r"\son[a-z]+=", html), "inline event handlers violate script-src 'self'"
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> violates script-src"


@pytest.mark.anyio
async def test_login_page_and_csp_header():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        page = await c.get("/login")
        assert page.status_code == 200 and "Entrar" in page.text
        csp = page.headers["content-security-policy"]
        assert "unsafe-inline" not in csp and "googleapis" not in csp
        me = await c.get("/api/v1/auth/me")
        assert me.json()["auth_enabled"] is False


@pytest.mark.anyio
async def test_vercel_serverless_entrypoint_normalization():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        for path in ("/", "/app/main.py", "/api/index.py"):
            res = await c.get(path)
            assert res.status_code == 200 and "Prompt Sanitizer" in res.text
        res_login = await c.get("/app/main.py/login")
        assert res_login.status_code == 200 and "Entrar" in res_login.text
