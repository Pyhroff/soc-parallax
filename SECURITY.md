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

This is a research prototype, not a production SIEM. Review authentication, secrets, network exposure, container configuration, and data retention before deploying it outside a local or isolated environment.

## Supported versions

Security fixes target the default branch. Older commits and research snapshots are not maintained as supported releases.
