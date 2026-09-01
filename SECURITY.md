# Security Policy

Sentinel is a security-focused project, but the current implementation is still an MVP.

## Reporting Issues

Please open a private security advisory or contact the maintainer before publishing details about exploitable vulnerabilities.

## Current Security Boundaries

Sentinel currently provides:

- API event collection
- Metadata redaction
- Threat scoring
- Incident creation
- Self-hosted deployment

Sentinel does not replace:

- A WAF
- API authentication
- Authorization checks
- Vulnerability scanning
- Packet inspection
- Full SIEM tooling

## Secret Handling

Do not send production secrets in request bodies or headers. Sentinel includes configurable redaction, but applications should still avoid collecting sensitive data whenever possible.
