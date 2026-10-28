"""Rate limiting with slowapi.

- Auth endpoints: 5 requests/minute per client IP (brute-force / credential stuffing).
- Task endpoints: 100 requests/minute per client IP (abuse / scraping).

Uses in-memory storage by default. Set RATE_LIMIT_STORAGE_URI=redis://... when
running more than one instance so limits are shared.
"""
import os

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.config import get_settings
from app.logging_config import log_security_event

_settings = get_settings()

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=os.environ.get("RATE_LIMIT_STORAGE_URI", "memory://"),
    enabled=_settings.rate_limit_enabled,
    headers_enabled=False,
)

AUTH_LIMIT = _settings.auth_rate_limit
TASK_LIMIT = _settings.task_rate_limit


def rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    log_security_event(
        "rate_limit_exceeded",
        ip=get_remote_address(request),
        path=request.url.path,
        limit=str(exc.detail),
    )
    return JSONResponse(
        status_code=429,
        content={"detail": "Too many requests. Please try again later."},
        headers={"Retry-After": "60"},
    )
