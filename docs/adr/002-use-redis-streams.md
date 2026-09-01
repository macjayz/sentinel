# ADR-002: Use Redis Streams For MVP Queueing

## Status

Accepted

## Context

SDK events should not be written directly to PostgreSQL. The ingestion service needs to accept bursts quickly and push work to background processors.

## Decision

Use Redis Streams for the MVP queue.

## Consequences

- The self-hosted stack remains small and easy to run.
- Worker consumer groups support asynchronous processing.
- The queue adapter can later move to BullMQ, NATS, or managed streaming without changing SDK contracts.
