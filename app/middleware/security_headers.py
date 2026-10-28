"""Adds security headers to every response (pure ASGI middleware - no buffering)."""
from starlette.types import ASGIApp, Message, Receive, Scope, Send

# API-only CSP: nothing should ever be rendered or framed. The /docs page (development
# only) needs the Swagger UI CDN, so it gets a slightly relaxed policy.
API_CSP = "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
DOCS_CSP = (
    "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; img-src 'self' data: https://fastapi.tiangolo.com; "
    "frame-ancestors 'none'"
)

STATIC_HEADERS = {
    b"x-content-type-options": b"nosniff",
    b"x-frame-options": b"DENY",
    # Legacy header; "0" is the current OWASP recommendation (the old XSS auditor caused bugs).
    b"x-xss-protection": b"0",
    b"strict-transport-security": b"max-age=63072000; includeSubDomains; preload",
    b"referrer-policy": b"no-referrer",
    b"permissions-policy": b"geolocation=(), camera=(), microphone=(), payment=()",
    b"cross-origin-opener-policy": b"same-origin",
    b"cross-origin-resource-policy": b"same-origin",
    b"cache-control": b"no-store",
}


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        csp = DOCS_CSP if path in ("/docs", "/redoc") else API_CSP

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() != b"server"]
                existing = {k.lower() for k, _ in headers}
                for k, v in STATIC_HEADERS.items():
                    if k not in existing:
                        headers.append((k, v))
                headers.append((b"content-security-policy", csp.encode()))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_wrapper)
