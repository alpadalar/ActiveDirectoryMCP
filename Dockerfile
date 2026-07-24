FROM python:3.11-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

COPY pyproject.toml requirements.in setup.py ./
COPY src/ ./src/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.in \
    && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.11-slim AS runtime

RUN apt-get update && apt-get install -y \
    libldap-2.5-0 \
    libsasl2-2 \
    libssl3 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"
ENV AD_MCP_CONFIG=/app/ad-config/config.json

# Non-root execution
RUN useradd -m -u 1000 aduser && chown -R aduser:aduser /app
USER aduser

# Expose HTTP port
EXPOSE 8813

ENTRYPOINT ["python", "-m", "active_directory_mcp.server_http", "--host", "0.0.0.0", "--port", "8813", "--path", "/activedirectory-mcp"]
