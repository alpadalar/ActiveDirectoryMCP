# Base image: python:3.13-slim pinned by digest.
# Re-verify with: docker buildx imagetools inspect python:3.13-slim
# uv 0.12.6 pinned by digest. Re-verify with: docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.12.6
FROM ghcr.io/astral-sh/uv:0.13.4@sha256:9f130421e930bfbdc563c00740466603f8723158e90297d07957c2294640262b AS uv

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS builder

COPY --from=uv /uv /usr/local/bin/uv

ENV UV_PYTHON_DOWNLOADS=never \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/app/.venv

WORKDIR /app

# Install strictly from uv.lock; fails if the lock is stale.
COPY pyproject.toml uv.lock README.md ./
COPY src/ ./src/

RUN uv sync --locked --no-dev --no-editable --no-cache --extra azure

FROM python:3.13-slim@sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f AS runtime

# curl is used by the docker-compose healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip uninstall -y pip setuptools wheel

WORKDIR /app

# venv and code stay root-owned and read-only for the runtime user
COPY --from=builder --chown=root:root /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    AD_MCP_CONFIG=/app/ad-config/config.json

# Non-root execution; aduser owns only the directories it must write to
RUN useradd -m -u 1000 aduser \
    && mkdir -p /app/logs \
    && chown aduser:aduser /app/logs
USER aduser

# Expose HTTP port
EXPOSE 8813

ENTRYPOINT ["python", "-m", "active_directory_mcp.server_http", "--host", "0.0.0.0", "--port", "8813", "--path", "/activedirectory-mcp"]
