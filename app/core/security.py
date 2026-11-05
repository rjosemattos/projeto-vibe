"""Security middlewares and privacy headers."""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Adds hardened security and privacy headers to all HTTP responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Anti-sniffing & frame protection
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"

        # Privacy guarantee: prevent caching of prompts and sensitive analysis in intermediate proxies or browser disk
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"

        # Content Security Policy for UI and API
        sb_host = ""
        if settings.SUPABASE_URL:
            # Extract domain for strict connect-src
            try:
                from urllib.parse import urlparse
                parsed = urlparse(settings.SUPABASE_URL)
                if parsed.netloc:
                    sb_host = f"https://{parsed.netloc} wss://{parsed.netloc} "
            except Exception:
                pass

        connect_src = f"'self' {sb_host}https://*.supabase.co wss://*.supabase.co".strip()

        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self'; "
            "font-src 'self'; "
            "img-src 'self' data: https://*.googleusercontent.com https://lh3.googleusercontent.com; "
            f"connect-src {connect_src}; "
            "base-uri 'none'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none';"
        )
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        if settings.AUTH_ENABLED and settings.COOKIE_SECURE:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response


class PayloadLimitMiddleware(BaseHTTPMiddleware):
    """Enforces strict body size limits to prevent DoS attacks."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    if int(content_length) > settings.MAX_PAYLOAD_BYTES:
                        return JSONResponse(
                            status_code=413,
                            content={
                                "detail": (
                                    f"Payload too large. Maximum allowed size is "
                                    f"{settings.MAX_PAYLOAD_BYTES} bytes."
                                )
                            },
                        )
                except ValueError:
                    return JSONResponse(
                        status_code=400,
                        content={"detail": "Invalid Content-Length header."},
                    )
        return await call_next(request)



class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-IP request throttling for the API (login has its own, stricter limit)."""

    async def dispatch(self, request: Request, call_next) -> Response:
        if request.url.path.startswith("/api/"):
            from app.auth.routes import client_ip, rate_limiter

            if not rate_limiter.allow(f"api:{client_ip(request)}", settings.RATE_LIMIT_API_PER_MIN):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Muitas requisições. Tente novamente em instantes."},
                    headers={"Retry-After": "60"},
                )
        return await call_next(request)
