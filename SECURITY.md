# Security Policy

## Scope

SOC PARALLAX is a research prototype for security telemetry analysis. It processes security-event data, exposes an API, and integrates with PostgreSQL, Neo4j, Ollama, and a web frontend.

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub's **Security** tab using **Report a vulnerability**. Do not open a public issue for an exploitable security problem.

Include:
- the affected component or file
- a minimal reproduction or proof of concept
- security impact
- relevant configuration or version details

Never include API keys, passwords, tokens, private telemetry, or other sensitive data in a public report.

## Important deployment note

This is a research prototype, not a production SIEM. Review authentication, secrets, network exposure, container configuration, data retention, and dependency versions before deploying it outside a local or isolated environment.

## Supported versions

Security fixes target the default branch. Older commits and research snapshots are not maintained as supported releases.

## Data and model trust boundaries

- Treat ingested EVTX, JSON, CSV, and other telemetry as untrusted data. The analysis pipeline should parse it as data and must not execute commands embedded in event fields.
- The default narrative backend is local Ollama, but `OLLAMA_URL` is configurable. Operators must verify that it points to an approved endpoint before sending telemetry or investigation context.
- LLM narratives are analyst assistance, not authoritative incident conclusions. The grounding guard constrains generated claims to supplied evidence, but it is not a formal guarantee against every model failure.
- The MITRE rulebook is a project-maintained subset and can lag the live ATT&CK catalog. Validate mappings before using them for operational reporting or compliance decisions.
- Evaluation results are research measurements on documented corpora; they are not a certification of detection coverage or production false-positive rates.
