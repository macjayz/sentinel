# Sentinel MVP Boundary

## Build Now

The first public version should prove that Sentinel can be installed into a real Node.js API, capture useful telemetry, detect suspicious behavior, and show it in a self-hosted dashboard.

Required capabilities:

- Express middleware for Node.js applications
- REST request capture
- GraphQL operation capture when GraphQL payloads are sent over HTTP
- Ethereum/EVM JSON-RPC method capture
- Request and response metadata
- Latency and error monitoring
- Endpoint discovery
- Authentication failure tracking
- Abnormal request-rate detection
- IP activity tracking
- Configurable sensitive-field redaction
- API Threat Score
- Incidents and events
- Dashboard with live updates
- Docker self-hosting

## Defer

These features are deliberately excluded until the core pipeline is working:

- Kubernetes operator
- Python SDK
- Go SDK
- Mobile SDKs
- Solana
- Machine-learning threat detection
- Enterprise SSO
- Billing
- Multi-region deployment
- Full SIEM integrations
- Packet-level network inspection
- WAF replacement
- Vulnerability scanning

## Success Criteria

- A developer can add Sentinel middleware to an Express app in under five minutes.
- Events are accepted by an ingestion API, queued, processed, and persisted.
- Sensitive values are redacted before storage.
- The dashboard shows endpoints, latency, errors, IP activity, threat scores, and incidents.
- Docker Compose starts the full stack locally.
- The repository has enough documentation and commit history to read like a serious security product.
