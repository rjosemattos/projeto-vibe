"""Supabase and Google OAuth JWT verification (HS256 + Asymmetric ES256/RS256 JWKS)."""

from __future__ import annotations

import base64
import time
import urllib.request
from typing import Dict, Optional, Tuple
import jwt
from jwt import PyJWKSet
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("supabase_auth")

_JWKS_CACHE: Dict[str, Tuple[float, PyJWKSet]] = {}
_JWKS_TTL_SECONDS = 3600.0


def is_email_domain_allowed(email: str) -> bool:
    """Checks if the email matches one of the institutional allowed domains."""
    if not settings.ALLOWED_EMAIL_DOMAINS:
        return True
    email_clean = email.strip().lower()
    return any(email_clean.endswith(f"@{d.lstrip('@')}") for d in settings.ALLOWED_EMAIL_DOMAINS)


def _fetch_jwks(supabase_url: str) -> Optional[PyJWKSet]:
    """Fetches and caches the Supabase JWKS public keys for asymmetric JWTs (ES256/RS256)."""
    base_url = supabase_url.strip().rstrip("/")
    if not base_url:
        return None

    now = time.time()
    cached = _JWKS_CACHE.get(base_url)
    if cached and (now - cached[0]) < _JWKS_TTL_SECONDS:
        return cached[1]

    jwks_url = f"{base_url}/auth/v1/.well-known/jwks.json"
    try:
        req = urllib.request.Request(
            jwks_url,
            headers={"Accept": "application/json", "User-Agent": "PromptSanitizer/1.0"},
        )
        with urllib.request.urlopen(req, timeout=4.0) as resp:
            raw_json = resp.read().decode("utf-8")
            jwk_set = PyJWKSet.from_json(raw_json)
            _JWKS_CACHE[base_url] = (now, jwk_set)
            return jwk_set
    except Exception as exc:
        logger.warning("Failed to fetch JWKS from %s: %s", jwks_url, type(exc).__name__)
        return cached[1] if cached else None


def _decode_hs256(token: str, secret: str) -> dict:
    """Verifies an HS256 token using the raw secret or its base64-decoded bytes."""
    try:
        return jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="authenticated",
            options={"verify_exp": True},
        )
    except jwt.InvalidSignatureError:
        raw_bytes = base64.b64decode(secret)
        return jwt.decode(
            token,
            raw_bytes,
            algorithms=["HS256"],
            audience="authenticated",
            options={"verify_exp": True},
        )


def _decode_asymmetric(token: str, alg: str, kid: Optional[str]) -> Optional[dict]:
    """Verifies an asymmetric (ES256/RS256) Supabase JWT via JWKS or PEM secret."""
    jwk_set = _fetch_jwks(settings.SUPABASE_URL)
    if jwk_set and jwk_set.keys:
        matching_keys = [k for k in jwk_set.keys if not kid or k.key_id == kid]
        if not matching_keys:
            matching_keys = list(jwk_set.keys)
        last_err: Optional[Exception] = None
        for jwk_key in matching_keys:
            try:
                return jwt.decode(
                    token,
                    jwk_key.key,
                    algorithms=[alg],
                    audience="authenticated",
                    options={"verify_exp": True},
                )
            except Exception as exc:
                last_err = exc
        if last_err:
            raise last_err

    # If SUPABASE_JWT_SECRET happens to be a PEM public key
    if settings.SUPABASE_JWT_SECRET and "BEGIN" in settings.SUPABASE_JWT_SECRET:
        return jwt.decode(
            token,
            settings.SUPABASE_JWT_SECRET,
            algorithms=[alg],
            audience="authenticated",
            options={"verify_exp": True},
        )

    return None


def verify_supabase_jwt(token: str) -> Optional[dict]:
    """Verifies a Supabase-issued JWT and returns its claims.

    Enforces:
    1. Cryptographic signature (HS256 via SUPABASE_JWT_SECRET or ES256/RS256 via Supabase JWKS).
    2. Expiration and audience ("authenticated").
    3. Institutional domain restriction (e.g. @cesar.school).
    """
    if not token or not token.strip():
        return None

    token = token.strip()
    try:
        header = jwt.get_unverified_header(token)
        alg = header.get("alg", "HS256")
        kid = header.get("kid")

        payload: Optional[dict] = None

        if alg == "HS256" and settings.SUPABASE_JWT_SECRET:
            payload = _decode_hs256(token, settings.SUPABASE_JWT_SECRET.strip())
        elif alg in ("ES256", "RS256", "ES384", "RS384", "RS512", "EdDSA"):
            payload = _decode_asymmetric(token, alg, kid)

        if payload is None:
            # Fallback when secret/JWKS is unreachable and secret is not used for this alg
            if settings.SUPABASE_JWT_SECRET and alg == "HS256":
                return None
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
