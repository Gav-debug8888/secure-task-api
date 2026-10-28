"""FastAPI application factory with security middleware."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded

from app.config import get_settings
from app.database import init_db
from app.logging_config import configure_logging, log_security_event
from app.middleware.rate_limiter import limiter, rate_limit_exceeded_handler
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routes import auth as auth_routes
from app.routes import tasks as task_routes

# Settings are validated here, at import time: a missing/weak JWT_SECRET_KEY or a
# wildcard CORS origin raises immediately and the process never starts.
settings = get_settings()
configure_logging()
logger = logging.getLogger("app")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    log_security_event("app_started", environment=settings.environment)
    yield


is_prod = settings.environment == "production"

app = FastAPI(
    title="Secure Task API",
    version="1.0.0",
    description="Security-hardened task manager API",
    lifespan=lifespan,
    # Interactive docs are disabled in production to reduce attack surface.
    docs_url=None if is_prod else "/docs",
    redoc_url=None if is_prod else "/redoc",
    openapi_url=None if is_prod else "/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_exceeded_handler)

# Middleware order: the last added runs first (outermost).
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,  # explicit list, never "*"
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type", "Authorization"],
    max_age=600,
)
app.add_middleware(SecurityHeadersMiddleware)
if is_prod:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_host_list)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    # Return field locations and messages only; never echo the submitted values back.
    errors = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("unhandled_error path=%s", request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


@app.get("/health", tags=["ops"])
def health():
    """Liveness probe. Intentionally reveals no version, hostname or dependency details."""
    return {"status": "ok"}


app.include_router(auth_routes.router)
app.include_router(task_routes.router)
