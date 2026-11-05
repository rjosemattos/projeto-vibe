"""Authentication service: Argon2id passwords, server-side sessions, lockout, CSRF."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.auth.store import get_store, iso, parse, utcnow
from app.core.config import settings

_hasher = PasswordHasher()  # Argon2id with library defaults (RFC 9106 low-memory profile)
# Verified against when the user does not exist, so timing does not reveal valid usernames
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-equalization")

COMMON_WEAK = {"password", "123456", "qwerty", "senha", "admin", "letmein", "welcome"}


@dataclass
class SessionInfo:
    user_id: int
    username: str
    is_admin: bool
    csrf_token: str


class AuthError(Exception):
    """Generic authentication failure (message is safe to show to the client)."""


def validate_password_strength(password: str, username: str = "") -> None:
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        raise ValueError(f"A senha deve ter pelo menos {settings.MIN_PASSWORD_LENGTH} caracteres.")
    if len(password) > 256:
        raise ValueError("A senha é longa demais.")
    lowered = password.lower()
    if lowered in COMMON_WEAK or (username and username.lower() in lowered):
        raise ValueError("Senha fraca: evite palavras comuns ou o nome de usuário.")
    if len(set(password)) < 5:
        raise ValueError("Senha fraca: use caracteres mais variados.")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def create_user(username: str, password: str, is_admin: bool = False) -> int:
    username = username.strip()
    if not (3 <= len(username) <= 64) or not all(c.isalnum() or c in "._-@" for c in username):
        raise ValueError("Usuário deve ter 3–64 caracteres (letras, números, . _ - @).")
    validate_password_strength(password, username)
    store = get_store()
    if store.query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
        raise ValueError("Usuário já existe.")
    cur = store.execute(
        "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)",
        (username, _hasher.hash(password), int(is_admin), iso(utcnow())),
    )
    return int(cur.lastrowid)


def set_password(username: str, password: str) -> None:
    validate_password_strength(password, username)
    store = get_store()
    if not store.query_one("SELECT 1 FROM users WHERE username = ?", (username,)):
        raise ValueError("Usuário não encontrado.")
    store.execute(
        "UPDATE users SET password_hash = ?, failed_count = 0, locked_until = NULL WHERE username = ?",
        (_hasher.hash(password), username),
    )
    store.execute(
        "DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?)", (username,)
    )


def authenticate(username: str, password: str) -> SessionInfo:
    """Verifies credentials and opens a session. Raises AuthError with a generic message."""
    generic = AuthError("Usuário ou senha inválidos.")
    store = get_store()
    now = utcnow()
    row = store.query_one("SELECT * FROM users WHERE username = ?", (username.strip(),))

    if row is None:
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except Exception:
            pass
        raise generic

    locked_until = parse(row["locked_until"])
    if locked_until and locked_until > now:
        # Still spend the hashing time, then report the same generic error
        try:
            _hasher.verify(_DUMMY_HASH, password)
        except Exception:
            pass
        raise AuthError("Conta temporariamente bloqueada. Tente novamente mais tarde.")

    try:
        _hasher.verify(row["password_hash"], password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        failed = row["failed_count"] + 1
        if failed >= settings.MAX_FAILED_LOGINS:
            store.execute(
                "UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?",
                (iso(now + timedelta(minutes=settings.LOCKOUT_MINUTES)), row["id"]),
            )
        else:
            store.execute("UPDATE users SET failed_count = ? WHERE id = ?", (failed, row["id"]))
        raise generic

    if row["disabled"]:
        raise generic

    if _hasher.check_needs_rehash(row["password_hash"]):
        store.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?", (_hasher.hash(password), row["id"])
        )
    store.execute("UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = ?", (row["id"],))
    return SessionInfo(row["id"], row["username"], bool(row["is_admin"]), "")


def open_session(user: SessionInfo) -> tuple[str, str]:
    """Creates a session; returns (cookie_token, csrf_token). Only the token hash is stored."""
    token = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(24)
    now = utcnow()
    store = get_store()
    # Cap concurrent sessions per user (oldest dropped)
    store.execute(
        "DELETE FROM sessions WHERE user_id = ? AND token_hash NOT IN ("
        "SELECT token_hash FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 4)",
        (user.user_id, user.user_id),
    )
    store.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_token, created_at, last_seen, expires_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            _hash_token(token),
            user.user_id,
            csrf,
            iso(now),
            iso(now),
            iso(now + timedelta(hours=settings.SESSION_MAX_HOURS)),
        ),
    )
    return token, csrf


def resolve_session(token: Optional[str]) -> Optional[SessionInfo]:
    """Returns the session for a cookie token, enforcing absolute and idle timeouts."""
    if not token or len(token) > 128:
        return None
    store = get_store()
    now = utcnow()
    token_hash = _hash_token(token)
    row = store.query_one(
        "SELECT s.*, u.username, u.is_admin, u.disabled FROM sessions s "
        "JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        (token_hash,),
    )
    if row is None:
        return None
    idle_limit = parse(row["last_seen"]) + timedelta(minutes=settings.SESSION_IDLE_MINUTES)
    if row["disabled"] or parse(row["expires_at"]) <= now or idle_limit <= now:
        store.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))
        return None
    store.execute("UPDATE sessions SET last_seen = ? WHERE token_hash = ?", (iso(now), token_hash))
    return SessionInfo(row["user_id"], row["username"], bool(row["is_admin"]), row["csrf_token"])


def close_session(token: Optional[str]) -> None:
    if token:
        get_store().execute("DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),))


def csrf_valid(session: SessionInfo, provided: Optional[str]) -> bool:
    return bool(provided) and hmac.compare_digest(session.csrf_token, provided)
