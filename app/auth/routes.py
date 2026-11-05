"""FastAPI dependencies and routes for authentication."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Deque, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from app.auth import service
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("auth")
COOKIE_NAME = "ps_session"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


# ----------------------------------------------------------------------------
# Rate limiting (in-memory sliding window; use the reverse proxy / Redis for multi-instance)
# ----------------------------------------------------------------------------
class RateLimiter:
    def __init__(self) -> None:
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str, limit: int, window: float = 60.0) -> bool:
        now = time.monotonic()
        hits = self._hits[key]
        while hits and now - hits[0] > window:
            hits.popleft()
        if len(hits) >= limit:
            return False
        hits.append(now)
        if len(self._hits) > 10000:  # bound memory
            for k in [k for k, v in self._hits.items() if not v][:5000]:
                self._hits.pop(k, None)
        return True

    def reset(self) -> None:
        self._hits.clear()


rate_limiter = RateLimiter()


def client_ip(request: Request) -> str:
    if settings.TRUST_PROXY_HEADERS:
        fwd = request.headers.get("x-forwarded-for")
        if fwd:
            return fwd.split(",")[-1].strip()  # last hop = the one added by our own proxy
    return request.client.host if request.client else "unknown"


# ----------------------------------------------------------------------------
# Dependencies
# ----------------------------------------------------------------------------
def _origin_ok(request: Request) -> bool:
    origin = request.headers.get("origin")
    if not origin:
        return True
    host = request.headers.get("host", "")
    return origin.split("://", 1)[-1] == host


def current_session(request: Request) -> service.SessionInfo:
    """Requires a valid session; enforces CSRF + Origin checks on state-changing requests."""
    session = service.resolve_session(request.cookies.get(COOKIE_NAME))
    if session is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Sessão inválida ou expirada.")
    if request.method not in SAFE_METHODS:
        if not _origin_ok(request) or not service.csrf_valid(session, request.headers.get("x-csrf-token")):
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Falha na verificação CSRF.")
    return session


def require_admin(session: service.SessionInfo = Depends(current_session)) -> service.SessionInfo:
    if not session.is_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Acesso restrito a administradores.")
    return session


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
auth_router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=256)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(..., max_length=256)
    new_password: str = Field(..., max_length=256)


@auth_router.get("/config")
async def auth_config():
    """Public frontend authentication configuration."""
    sb_enabled = bool(settings.SUPABASE_URL and settings.SUPABASE_ANON_KEY)
    return {
        "auth_enabled": settings.AUTH_ENABLED or sb_enabled,
        "supabase_enabled": sb_enabled,
        "supabase_url": settings.SUPABASE_URL,
        "supabase_anon_key": settings.SUPABASE_ANON_KEY,
        "allowed_domains": settings.ALLOWED_EMAIL_DOMAINS,
    }


@auth_router.get("/me")
async def me(request: Request):
    # 1. Check Bearer Token (Supabase / Google OAuth)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        from app.auth.supabase_jwt import verify_supabase_jwt
        payload = verify_supabase_jwt(token)
        if payload:
            email = payload.get("email") or payload.get("user_metadata", {}).get("email") or payload.get("sub", "")
            return {
                "auth_enabled": True,
                "authenticated": True,
                "username": email,
                "user_id": payload.get("sub"),
                "is_admin": False,
                "csrf_token": "bearer_auth",
            }

    # 2. Check Local Cookie Session
    if not settings.AUTH_ENABLED and not settings.SUPABASE_URL:
        return {"auth_enabled": False, "authenticated": True, "username": "local"}

    session = service.resolve_session(request.cookies.get(COOKIE_NAME))
    if session is None:
        return {"auth_enabled": True, "authenticated": False}
    return {
        "auth_enabled": True,
        "authenticated": True,
        "username": session.username,
        "is_admin": session.is_admin,
        "csrf_token": session.csrf_token,
    }


@auth_router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response):
    if not settings.AUTH_ENABLED:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Autenticação desativada.")
    if not _origin_ok(request):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Origem não permitida.")
    ip = client_ip(request)
    if not rate_limiter.allow(f"login:{ip}", settings.RATE_LIMIT_LOGIN_PER_MIN):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Muitas tentativas. Aguarde um minuto.")
    try:
        user = service.authenticate(payload.username, payload.password)
    except service.AuthError as exc:
        logger.warning("Login failed from %s", ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc))

    token, csrf = service.open_session(user)
    response.set_cookie(
        COOKIE_NAME,
        token,
        max_age=settings.SESSION_MAX_HOURS * 3600,
        httponly=True,
        secure=settings.COOKIE_SECURE,
        samesite="strict",
        path="/",
    )
    logger.info("Login ok: user_id=%s", user.user_id)
    return {"authenticated": True, "username": user.username, "is_admin": user.is_admin, "csrf_token": csrf}


@auth_router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(request: Request, response: Response):
    session = service.resolve_session(request.cookies.get(COOKIE_NAME))
    if session is not None and (
        not _origin_ok(request) or not service.csrf_valid(session, request.headers.get("x-csrf-token"))
    ):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Falha na verificação CSRF.")
    service.close_session(request.cookies.get(COOKIE_NAME))
    response.delete_cookie(COOKIE_NAME, path="/")
    return None


@auth_router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(payload: PasswordChangeRequest, session: service.SessionInfo = Depends(current_session)):
    try:
        service.authenticate(session.username, payload.current_password)
    except service.AuthError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Senha atual incorreta.")
    try:
        service.set_password(session.username, payload.new_password)  # also revokes all sessions
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return None
