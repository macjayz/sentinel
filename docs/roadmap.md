# Roadmap

Sentinel's goal is to be the tool teams use to answer one question: **is my RPC provider telling me
the truth?**

Everything below is ordered by how much it serves that question. Work that does not serve it is
explicitly deprioritized, including work that is already built.

---

## Phase 1 — Result capture and the first content-aware detectors

*The unlock. Nothing else on this roadmap is possible without it.*

The SDK currently discards RPC results and synthesizes a `200`/`500` status from whether the call
threw. Every differentiated detector needs the response body.

- [x] Extend the `evmRpc` event block with `blockTag`, `blockNumber`, `blockHash`, `resultHash`,
      `resultShape`, `rpcErrorCode`, `endpointHash`, `costUnits`, `shadowOfTraceId`
      ([spec](detectors.md#prerequisite-result-capture))
- [x] Result normalization and hashing — sorted keys, lowercased hex, canonical leading zeros.
      **This is the load-bearing piece.** Weak normalization makes D2 pure noise
- [ ] Stop modeling RPC as HTTP. `request.method: "POST"`, `path: "/rpc"`, and reusing
      `auth.failed` to mean "the RPC call failed" are all modeling debt that will block D1–D6
- [x] Endpoint hashing — **never persist an RPC URL**, it embeds the provider API key
- [x] Per-chain block-time table (mainnet, Base, Arbitrum, Optimism, Polygon) with a measured-median
      fallback for unknown chains
- [x] SDK captures results: `wrapEip1193Provider` and `createSentinelRpcClient` now record block
      metadata, result hash, result shape, and JSON-RPC errors returned inside a 200 body
- [x] Persist captured fields (`002_rpc_result_capture.sql`) with indexes shaped for D1–D6
- [x] **D1 — Stale head** ([spec](detectors.md#d1--stale-head))
- [x] **D3 — Silent failure** ([spec](detectors.md#d3--silent-failure))
- [x] **D6 — Cost and waste**, including duplicate-call detection within a block
      ([spec](detectors.md#d6--cost-and-waste))
- [ ] Dashboard: replace the generic RPC activity view with a provider-health view — head lag, silent
      failure rate, and cost per method per provider

**Done when:** Sentinel can point at a single provider and report staleness, silent failures, and
wasted spend that no other tool surfaces.

---

## Phase 2 — Cross-provider verification

*The flagship. This is the capability nobody else has.*

- [x] Multi-endpoint configuration: primary plus one or more verification endpoints per chain
- [x] Shadow client with **block pinning** — rewrite `latest` to the concrete resolved height before
      replaying. Comparing `latest` to `latest` measures head skew, not disagreement, and yields
      nothing but false positives
- [x] Deterministic-method allowlist. Never shadow `eth_gasPrice`, `eth_estimateGas`, or anything
      `pending`-tagged
- [x] Sampling budget with a hard `maxShadowCallsPerMinute` ceiling, defaulted low. Verification must
      never become the dominant cost
- [x] **D2 — Cross-provider disagreement** ([spec](detectors.md#d2--cross-provider-disagreement))
- [x] **D4 — Reorg lag**, including per-provider convergence time
      ([spec](detectors.md#d4--reorg-lag))
- [x] **D5 — Throttling as success** ([spec](detectors.md#d5--throttling-as-success))
- [ ] Disagreement incident view: the two results, the pinned height, both endpoints, the diff
- [x] Normalization test corpus built from real recorded responses across five public endpoints
      (`npm run record:corpus`). Confirms normalization collapses real key-order variance; cases the
      sample did not produce are covered separately by clearly-labelled synthetic mutations

**Done when:** Sentinel can catch two providers disagreeing at the same block height and show the
diff.

---

## Phase 3 — The measurement study

*The distribution strategy. Publishing novel data outperforms publishing code.*

Run Phase 2 against the major public RPC providers for 30 days and publish the results, with the
harness open sourced so anyone can reproduce it.

- [ ] Continuous measurement harness across the major providers on mainnet and two L2s
- [ ] 30-day collection: head lag distribution, silent failure rate, disagreement incidents,
      reorg convergence lag, throttling behavior under sustained load
- [ ] Public methodology write-up — reproducible, with the raw dataset published
- [ ] Comparison table with confidence intervals, not marketing claims
- [ ] Reproduction instructions so anyone can run it against their own providers

**Done when:** there is a citable public dataset on EVM RPC provider reliability that did not exist
before, and Sentinel is the tool that produced it.

**Rules for this phase:** report what the data says, including when it is unflattering to a
narrative that would be better for the project. Contact providers with findings before publishing.
Credibility here is the entire point, and it is spent instantly by overclaiming.

---

## Phase 4 — Adoption

- [ ] Publish `@sentinel/web3` to npm with real semver and a changelog
- [ ] Hosted docs with a five-minute quickstart
- [ ] Framework adapters: ethers.js, web3.js, plain `fetch`
- [ ] Standalone mode — run the detectors without the full self-hosted stack
- [ ] Additional chains: Solana JSON-RPC, Cosmos
- [ ] Slack and Discord incident notifications
- [ ] OpenTelemetry export
- [ ] Grafana dashboard templates

---

## Deprioritized

Already built and maintained, but no longer where the project's effort goes. These stay because they
support the RPC story — correlating a provider incident with the request that triggered it — not
because Sentinel competes on general observability.

- Express, REST, and GraphQL request monitoring
- Application error grouping
- Generic per-IP rate anomaly and credential-stuffing heuristics
- Project and user management UI
- API key rotation UI

Sentry, Datadog, and OpenTelemetry are better at general APM and always will be. Sentinel does not
try to win there.

---

## Shipped

**v0.1 — self-hosted pipeline.** Express SDK; ingestion API; Redis Streams queue; worker and threat
engine; PostgreSQL persistence; dashboard with request explorer and incident grouping; Docker
Compose self-hosting; health, readiness, and Prometheus metrics; OpenTelemetry spans and trace IDs
across the pipeline.

**v0.1 — multi-tenancy and auth.** Organizations, users, memberships, project-scoped API keys;
password-hashed accounts with hashed session tokens; server-enforced `owner`/`admin`/`developer`/
`viewer` roles on mutating routes; public signup onboarding; production-safe dashboard scoping with
no anonymous fallback.

**v0.1 — alerting.** Incident status workflows (open, acknowledged, resolved, ignored); webhook
destinations with exponential-backoff retries and terminal failure handling; configurable alert rule
engine over error rate, p95 latency, threat score, request volume, and auth failures.

**v0.1 — web3 foundation.** `@sentinel/web3` with EIP-1193 wrapper, viem-compatible transport, and
standalone JSON-RPC client; per-call recording of method, chain, provider, latency, and hard
failures; web3 threat rules for RPC method flooding, wallet transaction bursts, provider latency
degradation, and elevated provider failure rates.
