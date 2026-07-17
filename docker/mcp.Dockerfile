# syntax=docker/dockerfile:1
FROM python:3.11-slim

LABEL maintainer="IncidentOps AI"
LABEL description="IncidentOps AI — Runbook MCP Server"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir "mcp>=1.0" "httpx>=0.27"

COPY mcp_servers/ ./mcp_servers/

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 8090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8090/health || exit 1

ENTRYPOINT ["python", "mcp_servers/runbook_server/server.py"]
CMD ["--transport", "sse", "--port", "8090"]
