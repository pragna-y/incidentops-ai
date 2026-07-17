# IncidentOps AI

AI-Assisted Incident Management System

A software engineering project that demonstrates the use of AI to assist with
incident analysis, troubleshooting, and remediation planning. The application
processes application logs, retrieves relevant troubleshooting guidance, and
generates remediation suggestions through a modular workflow with human approval
before execution.


## Overview

IncidentOps AI is built to simulate a simplified incident response workflow used
by software and Site Reliability Engineering (SRE) teams.

The project focuses on software architecture, modular design, and AI-assisted
automation rather than fully autonomous decision making.

Main capabilities include:

- Log processing and analysis
- Sensitive data redaction
- Incident classification
- Runbook retrieval
- Remediation planning
- Human approval before execution
- Simulation of remediation steps


## Architecture

```
Application Logs
        │
        ▼
+----------------------+
| Offline Redaction    |
+----------------------+
        │
        ▼
+----------------------+
| Log Parser           |
+----------------------+
        │
        ▼
+----------------------+
| Metric Correlation   |
+----------------------+
        │
        ▼
+----------------------+
| AI Workflow          |
| - Triage             |
| - Research           |
| - Planning           |
| - Review             |
+----------------------+
        │
        ▼
+----------------------+
| Human Approval       |
+----------------------+
        │
        ▼
+----------------------+
| Simulation           |
+----------------------+
```

---

## Technologies

- Python
- Google ADK
- Model Context Protocol (MCP)
- Docker
- FastMCP
- Git


## Features

### Log Processing

- Reads and parses application log files
- Identifies common incident patterns
- Extracts structured information for analysis

### Security

- Performs offline redaction of sensitive information
- Prevents confidential data from being passed to the language model

### Runbook Retrieval

- Retrieves troubleshooting documentation through an MCP server
- Uses runbooks to provide relevant remediation guidance

### AI-Assisted Analysis

- Uses multiple AI agents to:
    - analyze incidents
    - retrieve supporting information
    - generate remediation plans
    - review recommendations

### Human Approval

- Requires user confirmation before executing remediation simulations

### Simulation

- Demonstrates the proposed remediation steps
- Does not modify real infrastructure


## Design Highlights

The project follows a modular architecture that separates different
responsibilities into independent components.

- Core models maintain application state.
- Services handle parsing, correlation, and preprocessing.
- Skills expose reusable functionality to AI agents.
- Agents coordinate the incident analysis workflow.
- Infrastructure modules manage CLI interaction and external communication.

This separation improves readability, maintainability, and future extensibility.


## Running the Project

Clone the repository

```bash
git clone <repository-url>
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run the application

```bash
python -m src.infra.cli
```


## Sample Workflow

1. Load an application log file.
2. Redact sensitive information.
3. Parse log events.
4. Correlate infrastructure metrics.
5. Retrieve relevant runbooks.
6. Generate remediation suggestions.
7. Review recommendations.
8. Request user approval.
9. Simulate remediation.


## Learning Outcomes

This project helped strengthen experience with:

- Python application development
- Modular software architecture
- AI-assisted workflows
- Model Context Protocol (MCP)
- Docker-based development
- Software testing
- Configuration management
- Version control with Git


## Future Improvements

Potential enhancements include:

- Integration with monitoring platforms
- Additional incident detection strategies
- Improved log parsing
- Expanded runbook library
- Web dashboard for incident visualization
- Cloud deployment
