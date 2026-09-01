# Contributing

Sentinel is in MVP development. Contributions should keep the first release focused on the ingestion pipeline, Node SDK, threat scoring, and dashboard.

## Development

```bash
npm install
npm run typecheck
npm test
npm run lint
npm run build
```

## Pull Request Guidelines

- Keep changes scoped to one capability.
- Add or update tests for shared schemas, scoring, ingestion, and worker behavior.
- Do not add unrelated frameworks or infrastructure services.
- Avoid committing generated build output.
- Keep secrets out of examples and documentation.

## Commit Style

Use short conventional-style commit messages, for example:

```text
feat: add graphql operation discovery
fix: preserve queued sdk events after ingestion failure
docs: document docker self-hosting flow
```
