"""Supabase and Google OAuth JWT verification."""

from __future__ import annotations

from typing import Optional
import jwt
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("supabase_auth")


def is_email_domain_allowed(email: str) -> bool:
    """Checks if the email matches one of the institutional allowed domains."""
    if not settings.ALLOWED_EMAIL_DOMAINS:
        return True
    email_clean = email.strip().lower()
    return any(email_clean.endswith(f"@{d.lstrip('@')}") for d in settings.ALLOWED_EMAIL_DOMAINS)


def verify_supabase_jwt(token: str) -> Optional[dict]:
    """Verifies a Supabase-issued JWT and returns its claims.

    Enforces:
    1. Cryptographic signature (when SUPABASE_JWT_SECRET is set).
    2. Expiration and audience ("authenticated").
    3. Institutional domain restriction (e.g. @cesar.school).
    """
    if not token or not token.strip():
        return None

    token = token.strip()
    try:
        if settings.SUPABASE_JWT_SECRET:
            # Full cryptographic verification with Supabase Project JWT secret
            payload = jwt.decode(
                token,
                settings.SUPABASE_JWT_SECRET,
                algorithms=["HS256", "RS256", "ES256"],
                audience="authenticated",
                options={"verify_exp": True},
            )
        else:
            # Fallback when secret is not configured: verify claims structure & expiration
            payload = jwt.decode(
                token,
                options={"verify_signature": False, "verify_exp": True},
            )
            if payload.get("aud") != "authenticated" or "sub" not in payload:
                return None

        # Institutional Domain Restriction Check (Zero Trust)
        email = payload.get("email") or payload.get("user_metadata", {}).get("email") or ""
        if not is_email_domain_allowed(email):
            logger.warning("Rejected user '%s': email domain is not in ALLOWED_EMAIL_DOMAINS", email)
            return None

        return payload
    except jwt.ExpiredSignatureError:
        logger.warning("Supabase JWT has expired")
        return None
    except Exception as exc:
        logger.warning("Supabase JWT verification failed: %s", type(exc).__name__)
        return None
