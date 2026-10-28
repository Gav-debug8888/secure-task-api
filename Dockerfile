# ---- Build stage: install dependencies into a virtualenv ----
FROM python:3.12-slim AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
COPY requirements.txt .
# pip is only needed at build time. Its vendored libraries (urllib3, msgpack,
# pkg_resources) carry their own CVEs that Trivy flags, so strip it from the venv.
RUN pip install -r requirements.txt && python -m pip uninstall -y pip

# ---- Runtime stage: minimal, non-root ----
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    DATABASE_URL=sqlite:////data/tasks.db

RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home app \
    && mkdir -p /data && chown app:app /data \
    && python -m pip uninstall -y pip

COPY --from=builder /opt/venv /opt/venv
WORKDIR /srv
COPY --chown=app:app app ./app

USER 10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

# --proxy-headers so client IPs (used by the rate limiter) are correct behind a TLS-terminating proxy.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--no-server-header"]
