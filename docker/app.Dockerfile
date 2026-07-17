# syntax=docker/dockerfile:1
FROM python:3.11-slim

LABEL maintainer="IncidentOps AI"
LABEL description="IncidentOps AI — Autonomous Incident Triage & Response Agent"

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (layer cache optimisation)
COPY pyproject.toml ./
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -e ".[dev]"

# Copy application source
COPY src/ ./src/
COPY mcp_servers/ ./mcp_servers/
COPY sample_logs/ ./sample_logs/
COPY tests/ ./tests/

# Create output directory
RUN mkdir -p /app/output

# Expose no ports (CLI application)
# Override ENTRYPOINT for interactive use:
#   docker run --rm -it incidentops-ai incidentops analyze --log sample_logs/db_pool_exhaustion.log

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV INCIDENTOPS_OUTPUT_DIR=/app/output

ENTRYPOINT ["incidentops"]
CMD ["--help"]
