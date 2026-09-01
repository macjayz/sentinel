# ADR-001: Use PostgreSQL For Durable Storage

## Status

Accepted

## Context

Sentinel stores API events, endpoint rollups, IP activity, and incidents. These records need reliable querying, transactional writes, indexes, and operational familiarity for self-hosted users.

## Decision

Use PostgreSQL as the primary durable database.

## Consequences

- Users can self-host Sentinel with a common, well-understood database.
- Analytics queries can start simple with SQL before introducing specialized storage.
- Time-series scale may eventually require partitioning, retention jobs, or a dedicated analytics store.
