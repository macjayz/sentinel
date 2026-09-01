# Architecture

Sentinel is split into four runtime layers: SDK, ingestion, processing, and dashboard.

## Data Flow

```text
Express application
  |
SDK middleware
  |
Ingestion API
  |
Redis Stream
  |
Worker
  |
PostgreSQL
  |
Analytics API
  |
WebSocket API
  |
Dashboard
```

## SDK

The Node SDK captures HTTP metadata inside the application process. It keeps payload capture conservative, applies local redaction, and sends batches to the ingestion API.

The SDK is not responsible for threat detection or persistence.

## Ingestion API

The ingestion API authenticates project keys, validates event schemas, rate-limits noisy clients, and writes accepted events to Redis Streams.

It does not perform long-running analysis in the request path.

## Queue

Redis Streams provide a simple self-hosted queue for the MVP. This can later be replaced by NATS or a managed stream without changing SDK contracts.

## Worker

Workers consume events, normalize endpoint metadata, calculate threat scores, create incidents, and write durable records into PostgreSQL.

## Database

PostgreSQL stores projects, API keys, raw events, endpoint rollups, IP rollups, and incidents.

## Dashboard

The dashboard uses the analytics API for historical data and WebSocket messages for live event updates.

## Web3 Integration

EVM JSON-RPC support is implemented as a traffic classifier and analyzer. Web3 is an integration, not the foundation of the product.
