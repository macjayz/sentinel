# ADR-003: Keep Ingestion Asynchronous

## Status

Accepted

## Context

Sentinel runs beside production APIs. Monitoring must not make user applications wait on analytics, threat scoring, or database writes.

## Decision

The ingestion API authenticates, validates, rate-limits, queues, and returns `202 Accepted`. Processing and persistence happen in workers.

## Consequences

- Request ingestion stays fast under normal conditions.
- Database latency does not directly block SDK clients.
- Operators need queue depth and failed job visibility as the platform matures.
