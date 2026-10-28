# ---- Build stage: install dependencies into a virtualenv ----
# Alpine: musl libc, no Debian packages, minimal CVE surface.
# All dependencies (bcrypt, uvloop, httptools) ship prebuilt musllinux wheels,
# so no compiler is needed in the builder or the runtime.
FROM python:3.12-alpine AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
# pip is only needed at build time; remove it so Trivy doesn't flag its bundled libs.
RUN pip install -r requirements.txt && python -m pip uninstall -y pip

# ---- Runtime stage: minimal Alpine, non-root ----
FROM python:3.12-alpine
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DATABASE_URL=sqlite:////data/tasks.db

# Apply any pending Alpine security patches, create a non-root user, set up data dir.
RUN apk upgrade --no-cache \
    && addgroup -S -g 10001 app \
    && adduser  -S -u 10001 -G app -H -D app \
    && mkdir -p /data && chown app:app /data \
    && python -m pip uninstall -y pip 2>/dev/null || true

COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=app:app app ./app

USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# --proxy-headers so client IPs (used by the rate limiter) are correct behind a TLS-terminating proxy.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
