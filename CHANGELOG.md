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
- Added `@sentinel/web3` with standalone RPC client, EIP-1193 wrapper, viem-compatible transport, and RPC dashboard visibility.
- Verified the live local pipeline against Postgres and Redis, including SDK-style seed traffic, worker persistence, grouped incidents, normalized endpoint discovery, and queue backlog metrics.
- Added incident status workflows, timeline records, alert destination management, and queued alert delivery records for high and critical incidents.
- Added webhook alert delivery with atomic queue claiming, exponential backoff retries, and terminal failure handling after repeated delivery attempts.
- Fixed the dashboard project switcher: analytics, incidents, API keys, and alerts endpoints now resolve the authenticated caller's requested project instead of always returning the demo project's data. Anonymous (unauthenticated) requests remain locked to the demo project. The dashboard now authenticates with the shared dev API key by default in both Docker Compose and local development, so this works without extra setup.
- Fixed the dashboard silently faking success when the API rejects a request (invalid webhook URL, invalid key name): rejected requests now surface the real error message instead of fabricating a local record that vanishes on the next refresh. A genuinely unreachable API still falls back to offline demo mode.
- Added a request detail view: clicking a row in the Request Explorer opens the full event metadata (trace ID, headers context, auth state, GraphQL/EVM fields, threat signals).
- Added Web3-specific threat rules: RPC method flooding, wallet transaction bursts against a rolling hourly baseline, RPC provider latency degradation against a 24-hour baseline, and elevated RPC provider failure rates. Web3-specific incident categories now take priority over the generic per-IP rate anomaly when both apply to the same traffic.
- Added a configurable alert rule engine: project-scoped threshold rules on error rate, p95 latency, threat score, request volume, and authentication failure count, evaluated on a rolling window every 30 seconds. Breached rules raise an incident through the existing incident workflow and alert delivery pipeline, with dashboard management for creating and enabling or disabling rules.
- Added application error grouping: the Express SDK now exposes `sentinelErrorHandler()` to capture the error type, message, and stack trace from failed requests, the worker fingerprints and groups matching errors by type, normalized message, and affected endpoint, and the dashboard's new Errors view shows occurrence counts, affected IPs, and first/last seen timestamps per group.
- Added real dashboard authentication: scrypt-hashed passwords, hashed opaque session tokens with 7-day expiry, and an owner account auto-bootstrapped on first startup from `SENTINEL_ADMIN_EMAIL`/`SENTINEL_ADMIN_PASSWORD`. Login, session validation, and logout are real API calls, not simulated. Project roles (owner/admin/developer/viewer) are now read from real `project_memberships` rows and enforced server-side on every mutating dashboard route (API keys, alert destinations, alert rules, incident status) whenever a session token is presented, independent of and in addition to existing project-scoped API key access.
- Added a root `ARCHITECTURE.md` covering system topology, the event abstraction, the worker's processing pipeline, the data model, and authentication/authorization trust boundaries, with diagrams. `docs/architecture.md` now points to it.
- Hardened for production readiness: upgraded Fastify 4 to 5 (resolves several high-severity advisories in Fastify and `find-my-way`), added a dedicated rate limit (10/minute) on `POST /v1/auth/login` independent of the global rate limit, and switched the API, worker, and dashboard Docker images to run as a non-root user.
- Added CodeQL analysis, a dependency review check on pull requests, a production-dependency `npm audit` step, and a Docker image build verification job to CI.
- Removed a broken README screenshot reference (`alert-workflows.png`) that pointed at a file that was never added.
- Added CI, issue templates, contribution guide, security policy, roadmap, and dashboard screenshot.
