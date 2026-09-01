# Sentinel

Self-hosted API security and observability for Node.js applications.

Sentinel monitors REST, GraphQL, WebSocket, webhook, and EVM JSON-RPC traffic through a lightweight SDK, an ingestion pipeline, a threat engine, and a dashboard. The MVP focuses on Express applications while keeping the architecture modular enough for additional runtimes and chains later.

## MVP Scope

Sentinel v0 targets:

- Node.js applications
- Express middleware
- REST and GraphQL request monitoring
- Ethereum/EVM JSON-RPC monitoring
- Request and response metadata
- Latency, error, endpoint, IP, and authentication failure tracking
- Configurable sensitive-field redaction
- Abnormal request-rate detection
- API Threat Score calculation
- Incidents and security events
- Real-time dashboard updates
- Docker-based self-hosting

Out of scope for the first release:

- Kubernetes operator
- Python, Go, and mobile SDKs
- Solana support
- Machine-learning threat detection
- Enterprise SSO
- Billing
- Multi-region deployment
- Full SIEM features
- Packet-level network inspection
- WAF replacement
- Vulnerability scanning

## Architecture

```text
User Application
  |
Sentinel SDK
  |
Ingestion API
  |
Event Queue
  |
Worker and Threat Engine
  |
PostgreSQL
  |
Analytics API and WebSocket API
  |
Dashboard
```

SDK traffic never writes directly to the database. Events move through the ingestion API and queue first, so monitored applications are protected from database latency and traffic bursts.

## Packages

The repository is organized as a TypeScript monorepo:

- `apps/api`: ingestion, analytics, and WebSocket API
- `apps/worker`: queue consumer, aggregation, and incident creation
- `apps/dashboard`: operator dashboard
- `packages/sdk-node`: Express middleware and Node client
- `packages/shared`: common schemas, redaction, scoring, and types
- `infra`: Docker Compose and database migrations

## Status

Sentinel is under active MVP implementation.

## Local Development

Install dependencies:

```bash
npm install
```

Run the full self-hosted stack:

```bash
docker compose up --build
```

Run services locally:

```bash
npm run dev
```

Use the Express example after the API is running:

```bash
npm run dev -w examples/express
```

The dashboard runs at `http://localhost:5173` and the API runs at `http://localhost:8080`.
