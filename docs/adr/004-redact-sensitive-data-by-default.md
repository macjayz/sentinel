# ADR-004: Redact Sensitive Data By Default

## Status

Accepted

## Context

API observability tools can accidentally collect secrets, credentials, tokens, and private Web3 material.

## Decision

Sentinel redacts common sensitive headers and payload fields by default. Users can add custom redaction fields.

## Consequences

- The default developer experience is safer.
- Debugging payloads may require explicit configuration.
- Future releases should add payload capture controls, hashed IP options, and retention policies.
