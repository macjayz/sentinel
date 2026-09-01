# Roadmap

## v0.1 MVP

- Express SDK
- Ingestion API
- Redis Streams queue
- Worker and threat engine
- PostgreSQL persistence
- Dashboard overview
- Docker Compose self-hosting
- Health, readiness, and runtime metrics
- Request explorer with method, status, IP, path, and threat filters
- Grouped security incidents with affected endpoint, attacker IPs, duration, and request count
- OpenTelemetry span hooks and trace IDs across the Sentinel pipeline
- Organization, user, membership, role, and project-scoped API key foundation
- Dashboard sign-in shell, operator role context, and project switcher
- API key list, create, and revoke workflows

## v0.2 Product Hardening

- Project management UI
- Backed password sessions for the dashboard
- API key rotation and scoped permissions
- SDK retry backoff controls
- Worker dead-letter stream
- Endpoint trend charts
- Incident status updates
- WebSocket event fanout from worker results

## v0.3 Integrations

- Webhook alert destinations
- Slack and Discord notifications
- OpenTelemetry export
- GitHub issue creation for incidents
- NATS queue adapter

## Later

- Python SDK
- Go SDK
- Kubernetes deployment templates
- Enterprise auth
- Additional Web3 networks
- Rule marketplace
