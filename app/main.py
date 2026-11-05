"""Main FastAPI application entry point for Prompt Sanitizer."""

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.auth.routes import auth_router
from app.api.rules_routes import rules_router
from app.core.config import settings
from app.core.logging import get_logger, setup_logging
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from app.core.security import PayloadLimitMiddleware, RateLimitMiddleware, SecurityHeadersMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan setup and teardown."""
    setup_logging(settings.LOG_LEVEL)
    logger = get_logger("main")
    if settings.AUTH_ENABLED and not settings.DEBUG:
        missing = [n for n in ("ENCRYPTION_KEY", "BLIND_INDEX_KEY") if not getattr(settings, n)]
        if missing:
            raise RuntimeError(
                "AUTH_ENABLED exige chaves explícitas em produção: defina "
                + ", ".join(f"PROMPT_SANITIZER_{n}" for n in missing)
            )
    mode = "hosted (auth enabled)" if settings.AUTH_ENABLED else "local mode"
    logger.info("Starting %s v%s in %s", settings.APP_NAME, settings.APP_VERSION, mode)
    yield
    logger.info("Shutting down %s", settings.APP_NAME)


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Privacy-first guardrail for sanitizing conversational AI prompts.",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url=None,
    lifespan=lifespan,
)

# Attach security & privacy middlewares
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
if settings.ALLOWED_HOSTS != ["*"]:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)
app.add_middleware(PayloadLimitMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Accept", "X-User-Id", "X-CSRF-Token"],
)

# Custom global exception handler: prevents internal tracebacks leaking in responses
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger = get_logger("exception_handler")
    logger.error("Unhandled error: %s", type(exc).__name__)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Prompt data was not stored or logged."},
    )


# Include API routes
app.include_router(router)
app.include_router(auth_router)
app.include_router(rules_router)

# Serve static assets
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.isdir(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.api_route("/login", methods=["GET", "HEAD"], include_in_schema=False)
async def serve_login():
    """Serve the sign-in page."""
    return FileResponse(os.path.join(static_dir, "login.html"), media_type="text/html")


@app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
async def serve_index():
    """Serve the single-page application interface."""
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path, media_type="text/html")
    return JSONResponse({"message": f"{settings.APP_NAME} running. Static index.html not found."})

