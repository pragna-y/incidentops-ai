# IncidentOps AI

**Autonomous Incident Triage & Response Agent**
*Portfolio / Resume Project — Principal Software Engineer & AI Systems Architect*

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![Google ADK](https://img.shields.io/badge/Google-ADK-orange.svg)](https://google.github.io/adk-docs/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Overview

IncidentOps AI is a production-quality, multi-agent system that assists Site
Reliability Engineers (SREs) during production incidents. Built to demonstrate
senior-level software architecture skills: multi-agent AI orchestration, security
engineering, protocol-based design, and full-stack deployability.

```
Production Log File
        │
        ▼
┌─────────────────┐
│ Security Gate   │  Offline regex redaction — zero PII reaches the LLM
│ (OfflineRedactor)│
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Log Parser     │  Structures events, detects anomalies
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Metric Correlator│  Maps scenario to infrastructure metrics snapshot
└────────┬────────┘
         │
         ▼
┌────────────────────────────────────────────┐
│            Google ADK Agent Pipeline        │
│                                            │
│  ┌──────────┐   ┌────────────┐             │
│  │  Triage  │   │ Researcher │ ← MCP Server│
│  │  Agent   │──▶│  Agent     │   (Runbooks)│
│  └──────────┘   └─────┬──────┘             │
│                        │                   │
│  ┌──────────┐   ┌──────▼──────┐            │
│  │Reflector │◀──│  Planner    │            │
│  │  Agent   │   │  Agent      │            │
│  └──────────┘   └─────────────┘            │
└──────────────────────┬─────────────────────┘
                        │
                        ▼
            ⚠  Human Approval Gate (HITL)
                        │
                        ▼
              Simulation Engine
          (Dry-run — no real changes)
```

---

## Key Skills Demonstrated

| Skill | Implementation |
|-------|----------------|
| **Multi-Agent AI** | 4 Google ADK `LlmAgent` instances with shared state and tool calling |
| **MCP (Model Context Protocol)** | FastMCP server exposing SRE runbooks; `mcp` client SDK with stdio transport |
| **Security Engineering** | Offline PII redaction gate (7 rule types) — LLM never sees raw sensitive data |
| **Clean Architecture** | Layered: domain → services → skills → agents → infra; zero circular imports |
| **Protocol-Based Design** | `RedactorProtocol` allows Google Cloud DLP swap-in without touching agent code |
| **Human-in-the-Loop (HITL)** | Explicit CLI approval gate locked by `ApprovalStatus` enum before any simulation |
| **Self-Reflection** | Dedicated `ReflectorAgent` critiques plans, adjusts confidence, flags escalation |
| **Deployability** | Two Dockerfiles + Docker Compose; fully reproducible, no cloud config required |
| **Testing** | 55 tests (42 unit + 13 integration) — all passing, no API key required |

---

## Features

| Feature | Description |
|---------|-------------|
| **Security Redaction** | Offline regex engine redacts IPs, emails, tokens, JWTs, API keys before any LLM call |
| **Log Parsing** | Structures raw logs into typed events with keyword-based anomaly detection |
| **Metric Correlation** | Maps incident to infrastructure metrics (CPU, memory, DB pool, JVM heap, etc.) |
| **MCP Runbook Server** | FastMCP server exposing SRE runbooks as tools via stdio/SSE transport |
| **Multi-Agent Pipeline** | 4 Google ADK agents (Triage → Researcher → Planner → Reflector) |
| **Human-in-the-Loop** | Explicit CLI approval required before simulation runs |
| **Simulation Engine** | Dry-run report showing what would be executed — no real infra changes |
| **Audit Trail** | Every agent action recorded in `IncidentState` with timestamps |
| **Dockerized** | App + MCP server each have dedicated Dockerfiles + Compose file |

---

## Quick Start

### Prerequisites

- Python 3.11+
- [Google API Key](https://aistudio.google.com/apikey) *(only for the `analyze` command)*

### Installation

```bash
# Clone / extract the project
cd incidentops-ai

# Create virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
source .venv/bin/activate     # Linux/macOS

# Install all dependencies
pip install -e ".[dev]"

# Configure API key (only needed for the analyze command)
copy .env.example .env
# Edit .env → set GOOGLE_API_KEY=your-key-here
```

### Commands

#### `triage` — Security + Parsing Pipeline *(no API key needed)*

Redacts the log, detects anomalies, correlates metrics, fetches the runbook via MCP.

```bash
incidentops triage --log sample_logs/db_pool_exhaustion.log
incidentops triage --log sample_logs/cpu_spike.log --save
incidentops triage --log sample_logs/memory_leak.log --no-preview
```

#### `analyze` — Full Multi-Agent Pipeline *(API key required)*

Runs all 4 ADK agents → presents recommendation → human approval → simulation.

```bash
set GOOGLE_API_KEY=your-key-here

incidentops analyze --log sample_logs/db_pool_exhaustion.log
incidentops analyze --log sample_logs/memory_leak.log --save-report
```

---

## Architecture

### Project Layout

```
incidentops-ai/
├── src/
│   ├── config.py              # Pydantic settings (env var overrides)
│   ├── core/
│   │   ├── entities.py        # Pure domain models — no infra imports
│   │   ├── interfaces.py      # RedactorProtocol (DLP plug-in ready)
│   │   └── state.py           # IncidentState — shared agent working memory
│   ├── services/
│   │   ├── redactor.py        # OfflineRedactor (7 rule types)
│   │   ├── parser.py          # LogParser + anomaly detection
│   │   └── correlator.py      # MetricCorrelator (scenario → metrics)
│   ├── skills/                # ADK agent tool functions (plain Python)
│   │   ├── log_tools.py       # 6 tools — Triage Agent
│   │   ├── metric_tools.py    # 2 tools — Triage Agent
│   │   ├── runbook_tools.py   # 4 tools — Researcher Agent
│   │   └── simulation_tools.py # 6 tools — Planner + Reflector + Simulation
│   ├── agents/
│   │   └── orchestrator.py    # IncidentOrchestrator (4-agent sequential pipeline)
│   └── infra/
│       ├── cli.py             # Typer CLI (triage + analyze commands)
│       └── mcp_client.py      # MCP client (stdio transport + local fallback)
├── mcp_servers/
│   └── runbook_server/
│       ├── server.py          # FastMCP server (list/get/search tools)
│       └── data/              # 3 production-quality SRE runbooks (markdown)
├── sample_logs/               # 3 realistic incident log files
├── tests/
│   ├── unit/                  # 42 redaction unit tests (no API key)
│   └── integration/           # 13 end-to-end pipeline tests (no API key)
├── docker/
│   ├── app.Dockerfile
│   └── mcp.Dockerfile
├── docker-compose.yml
└── pyproject.toml
```

### Key Design Decisions

1. **Security First** — The `OfflineRedactor` is always the first gate. The LLM never sees raw PII. Extensible to Google Cloud DLP via `RedactorProtocol` adapter.
2. **Pure Domain Models** — `entities.py` has zero infrastructure imports — fully serializable, easy to test, and framework-agnostic.
3. **State as Working Memory** — `IncidentState` (Pydantic model) is the single source of truth passed between all agents and pipeline stages.
4. **MCP with Local Fallback** — `RunbookClient` gracefully falls back to local files if the MCP server is unavailable — the demo always works offline.
5. **HITL by Design** — The simulation engine checks `ApprovalStatus.APPROVED` before running — the gate cannot be bypassed programmatically.
6. **Tool Functions, Not Methods** — ADK tools are plain Python functions, making them independently testable and composable without ADK present.

---

## Running Tests

```bash
# All tests — no API key needed
pytest tests/ -v

# Unit only
pytest tests/unit/ -v

# Integration only
pytest tests/integration/ -v

# With coverage report
pytest --cov=src --cov-report=term-missing
```

**Current result: 55/55 passed**

---

## Docker

```bash
# Build and start all services (MCP server + app)
docker compose up --build

# Run triage (no API key needed)
docker compose run app triage --log sample_logs/db_pool_exhaustion.log

# Run full multi-agent analysis
docker compose run app analyze --log sample_logs/memory_leak.log

# MCP server only (SSE transport on port 8090)
docker compose up mcp-server
```

---

## Sample Incidents

| Scenario | Log File | Key Signals |
|----------|----------|-------------|
| DB Pool Exhaustion | `db_pool_exhaustion.log` | 100% pool utilisation, JDBC timeouts, retry storm |
| CPU Spike | `cpu_spike.log` | 97% CPU, thread pool saturated, 89 errors/min |
| Memory Leak | `memory_leak.log` | JVM heap at 3.7/4.0 GB, GC pauses >2s, OOMKilled |

---

## Technical Stack

- **Language:** Python 3.11+
- **AI Framework:** Google ADK (`google-adk`) — `LlmAgent`, `Runner`, `InMemorySessionService`
- **LLM:** Gemini 2.0 Flash (via `google-genai`)
- **MCP:** `mcp` SDK — FastMCP server (stdio + SSE transports)
- **Validation:** Pydantic v2, pydantic-settings
- **CLI:** Typer + Rich (panels, progress spinners, tables)
- **Testing:** pytest, pytest-cov, pytest-anyio
- **Containers:** Docker + Docker Compose

---

## License

MIT — See [LICENSE](LICENSE)
