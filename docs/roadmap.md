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
- Web3 RPC SDK with EIP-1193 and viem-compatible transport helpers
- RPC dashboard view with method, provider, chain, latency, and threat context
- Live local pipeline verification with Postgres, Redis, ingestion, worker persistence, incidents, and dashboard reads
- Incident status workflows with open, acknowledged, resolved, and ignored states
- Webhook alert destinations and queued alert delivery records
- Webhook alert delivery with exponential backoff retries and terminal failure handling
- Web3 threat rules: RPC method flooding, wallet transaction bursts, provider latency degradation, and elevated provider failure rates
- Configurable alert rule engine: error rate, p95 latency, threat score, request volume, and authentication failure thresholds that raise incidents through the existing alert delivery pipeline
- Application error grouping: SDK error capture, worker-side fingerprinting by type/message/endpoint, and a dashboard Errors view with occurrence counts and affected IPs
- Real dashboard authentication: password-hashed accounts, hashed session tokens, and server-enforced project roles (owner/admin/developer/viewer) on mutating routes

## v0.2 Product Hardening

- Project management UI
- User management UI: invite or create additional dashboard accounts and assign project roles
- API key rotation and scoped permissions
- SDK retry backoff controls
- Worker dead-letter stream
- Endpoint trend charts
- Per-delivery response detail and delivery history drill-down
- WebSocket event fanout from worker results
- Configurable web3 threat rule thresholds
- Error group detail view with sample stack traces and occurrence history

## v0.3 Integrations

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
