# Changelog

All notable changes to Sentinel will be documented in this file.

## 0.1.0-alpha

Initial alpha release.

- Added TypeScript monorepo structure.
- Added shared event schemas, redaction helpers, route normalization, and heuristic risk scoring.
- Added Express SDK with batching, buffering, retries, redaction, request metadata, response metadata, GraphQL capture, and EVM JSON-RPC capture.
- Added Fastify ingestion and analytics API.
- Added Redis Streams queue integration.
- Added worker for threat scoring and incident creation.
- Added PostgreSQL schema migration.
- Added React dashboard with live status and offline demo mode.
- Added Docker Compose self-hosting configuration.
- Added demo traffic seeding script.
- Added health, readiness, runtime metrics, request IDs, and dashboard system status widgets.
- Added request explorer API and dashboard view with filters.
- Added grouped incident fingerprints with affected endpoints, source IPs, request counts, and last seen timestamps.
- Added OpenTelemetry span hooks and trace IDs across SDK, ingestion, queue, worker, storage, WebSocket, and request explorer views.
- Added organization, user, role, membership, and project-scoped API key schema.
- Added project-scope enforcement for ingestion and analytics queries.
- Added dashboard sign-in shell, operator role display, and project switcher.
- Added API key list, create, and revoke endpoints with dashboard key management UI.
- Added CI, issue templates, contribution guide, security policy, roadmap, and dashboard screenshot.
