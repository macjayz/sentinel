# Detectors

Every detector here attacks one assumption: **that an RPC call returning `200 OK` returned the
truth.**

Sentinel's current recorder branches only on whether the provider call threw. A provider that
answers instantly, from a node 40 blocks behind, with `result: null`, is recorded as a healthy
200 with excellent latency. D1–D6 close that gap.

Each detector below specifies its inputs, its firing condition, its false-positive handling, and
what it costs to run. Detectors marked **Shipping** exist in `packages/shared/src/index.ts`
(`assessThreat`) today.

---

## Prerequisite: result capture

D1–D6 all depend on data the SDK does not currently collect. `RpcRecorder.capture()` records the
request and a synthesized status code; it discards the result entirely.

Phase 1 extends the `evmRpc` block of `SentinelEvent` with:

| Field | Purpose | Notes |
|---|---|---|
| `blockTag` | The tag as written by the caller (`latest`, `pending`, `finalized`, or a height) | Distinguishes caller intent from resolved height |
| `blockNumber` | The concrete height the call actually resolved against | Required for any same-height comparison |
| `blockHash` | Hash at that height, when the response carries one | Reorg tracking |
| `resultHash` | Normalized hash of the result value | Comparison without storing raw chain data |
| `resultShape` | `null` \| `empty_array` \| `empty_data` \| `value` \| `error_in_body` | Cheap silent-failure signal |
| `resultCount` | Number of entries in an array result | Detects silently truncated pages |
| `rpcErrorCode` | JSON-RPC error code found inside a 200 body | Providers do this more than you would expect |
| `endpointHash` | Hash of the RPC URL | **Never store the URL — it embeds the API key** |
| `costUnits` | Provider-weighted cost for this method | Cost accounting |
| `shadowOfTraceId` | Links a verification call to the primary call it shadows | Cross-provider comparison |

**Why hash the result instead of storing it.** Raw results are large, sometimes contain user
balances and addresses, and are useless for comparison in raw form. A normalized hash answers "did
these two providers agree" without Sentinel becoming a database of chain state. Normalization must
sort object keys, lowercase hex, and strip leading-zero variance before hashing, or providers will
appear to disagree over formatting.

**Why hash the endpoint.** `https://eth-mainnet.g.alchemy.com/v2/<KEY>` is a credential. Sentinel
must be able to distinguish two endpoints of the same provider without ever persisting one.

---

## D1 — Stale head

**Status: implemented.**

**Catches:** a provider serving a chain head that has stopped advancing, or that lags the fastest
provider you use.

**Inputs:** `eth_blockNumber` responses, plus `blockNumber` resolved on any `latest`-tagged call,
tracked per `endpointHash`.

**Fires when either:**
- The provider's observed head has not advanced for more than `staleMultiplier × chainBlockTime`
  (default `3×`; 36s on mainnet, 6s on an L2 with 2s blocks), while Sentinel is still receiving
  successful responses from it, **or**
- The provider's head is behind the maximum head observed across all endpoints for that chain by
  more than `maxHeadLagBlocks` (default 3 on mainnet).

**False positives to handle:**
- Low-traffic projects produce sparse samples. Do not fire on fewer than 3 observations in the window.
- Chains with irregular block times (or an L2 in a sequencer pause) need a per-chain block-time table,
  not a global constant. The table ships for mainnet, Base, Arbitrum, Optimism, Polygon and Sepolia;
  unknown chains fall back to the mean block interval measured over the observation window.
- A deliberately `finalized`-tagged call is *supposed* to lag. Exclude non-`latest` tags.

**Cost:** free. Derived entirely from calls the application already makes.

---

## D2 — Cross-provider disagreement

**Status: implemented.** Off unless a `verify` block is configured.

**The flagship detector.** Catches two providers returning different results for the same call at
the same block height. At equal height, a mismatch is either a provider bug or an unpropagated
reorg — both are worth waking someone up for, and neither is visible to any existing tool.

**Inputs:** a sampled fraction of read-only calls, replayed against one or more secondary endpoints.

**Method:**
1. Sample at rate `shadowSampleRate` (default `0.01`) from an allowlist of deterministic read
   methods: `eth_call`, `eth_getBalance`, `eth_getCode`, `eth_getStorageAt`, `eth_getLogs`,
   `eth_getTransactionReceipt`, `eth_getBlockByNumber`.
2. **Pin the block.** Rewrite `latest` to the concrete height the primary resolved to. This is the
   single most important step — comparing against `latest` on both sides measures head skew, not
   disagreement, and produces nothing but false positives.
3. Issue the pinned call to each secondary endpoint, tagged `shadowOfTraceId`.
4. Normalize and hash both results. Compare.

**Fires when:** `resultHash` differs across endpoints for the same `(method, params, blockNumber)`.

**Severity:** graded by method. A disagreeing `eth_getBalance` or `eth_call` is critical — it means
your app can show different users different numbers. A disagreeing `eth_getLogs` is usually
truncation (see D3) and should be classified as such rather than as disagreement.

**False positives to handle:**
- **Formatting variance is the main source.** Providers differ on hex leading zeros, `null` vs
  omitted fields, log ordering, and receipt field sets. Normalization must be aggressive and
  well-tested, or D2 is noise. This is the hard engineering in the whole project.
  Measured against five public endpoints
  ([corpus](../packages/shared/corpus/README.md)): all five returned semantically identical
  results for all nine calls, differing only in key order — up to four distinct orderings for a
  single `eth_getLogs` response. Normalization collapses that to one hash while still separating
  genuinely different values.
- One provider not yet having the block — treat "block not found at pinned height" as a D1 stale-head
  observation, not a disagreement.
- Non-deterministic methods (`eth_gasPrice`, `eth_estimateGas`, anything `pending`) must never be
  shadowed. Enforce with an allowlist, not a denylist.

**What is actually being verified.** When the original call named a concrete height, the
comparison audits answers to exactly that question. When it used `latest`, the height that
`latest` resolved to is not recoverable from the response — so verification instead re-probes
every endpoint, *including the primary*, at a freshly resolved height. That measures whether the
providers agree rather than auditing one specific response, and it is the only form of the
comparison that is free of head-skew false positives. The primary is added to the fan-out
automatically, so every sample yields a set of directly comparable observations.

**Cost:** `sampleRate × (secondaryCount + 1)` extra calls, on endpoints you configure, plus at
most one `eth_blockNumber` per `headCacheMs` to resolve a pin target. Bounded by a hard
`maxCallsPerMinute` ceiling (default 60) that is checked before every fan-out, so verification can
never become the dominant cost. Defaults: `sampleRate` 0.01, verification disabled entirely unless
endpoints are configured.

---

## D3 — Silent failure

**Status: implemented,** except the cross-provider log comparison, which needs D2.

**Catches:** `200 OK` responses that carry no usable answer.

**Inputs:** `resultShape`, `rpcErrorCode`, and method-specific expectations.

**Fires when any of:**
- `resultShape` is `error_in_body` — a JSON-RPC error object inside a success response.
- `eth_getTransactionReceipt` returns `null` for a hash the same provider previously reported as
  mined.
- `eth_getLogs` returns an empty array for a range where another endpoint returned logs at the same
  pinned height (overlaps D2, and should be attributed to D3 because the cause is truncation).
- `eth_getLogs` returns exactly the provider's known page limit — a strong indicator of silent
  truncation, since providers commonly cap results without setting an error.
- `eth_call` returns `0x` where a prior identical call at an earlier block returned data.

**False positives to handle:**
- Empty is often legitimately correct. Every rule above is comparative — it fires on a *change* or a
  *disagreement*, never on emptiness alone. Do not add an "empty result" rule without a comparison.
- Rather than maintaining a table of provider page limits, the implementation treats the largest
  result count seen from an endpoint as a suspected ceiling only once it has recurred at least three
  times. A one-off maximum is a coincidence; a repeated exact ceiling is a cap.

**Cost:** free for the in-body checks; the comparative checks ride on D2's samples.

---

## D4 — Reorg lag

**Status: implemented.**

**Catches:** providers that keep serving a block after it has been reorged out, and measures how
deep the reorg went.

**Inputs:** `(chainId, endpointHash, blockNumber) → blockHash` observations over time.

**Fires when:** a previously-observed height reports a different `blockHash`. Record the reorg
depth (how many heights changed), which endpoint observed the new chain first, and the lag before
each other endpoint converged.

**Why it matters beyond alerting:** reorg-lag-per-provider is a genuinely novel measurement. Nobody
publishes it. A provider that is consistently 2 blocks slow to abandon a reorged chain is serving
doomed state to every one of its users, and this detector is the only way to know.

**False positives to handle:**
- A one-block reorg on mainnet is normal and is recorded with zero weight. Even at depth ≥ 2 the
  `reorg_detected` signal is scored below the incident threshold on purpose: a reorg is the chain's
  behaviour, not the provider's fault. The actionable finding is `reorg_lag` — a provider still
  serving a block its peers have abandoned — which does raise an incident.
- Uncle/ommer blocks on some chains will look like reorgs; scope the tracker to canonical-chain
  responses only.

**Cost:** free. Derived from block hashes already present in responses.

---

## D5 — Throttling as success

**Status: implemented.**

**Catches:** rate limiting that does not arrive as a clean `429`.

**Inputs:** status codes, provider-specific throttle error codes, latency distribution, and D3's
result-shape signals.

**Fires when:**
- Explicit throttle responses exceed `throttleRateThreshold` of requests in the window, or
- A latency cliff (p95 stepping above `3×` baseline) coincides with a rise in empty or truncated
  results — the signature of soft throttling.

**False positives to handle:**

- A latency cliff alone is already covered by `provider_degradation`. The soft rule requires
  latency degradation **and** result degradation together; either on its own produces nothing.
- The throttle-message pattern is deliberately narrow. A loose one ("exceeded") would match
  `gas limit exceeded` and turn every reverted call into a throttling finding.
- Degradation rates are measured only over events that carry a result shape, so traffic recorded
  before result capture existed cannot dilute the ratio and mask a real decline.
- Explicit throttling suppresses the inferred finding: when both hold, only `provider_throttling`
  is reported, since it names the cause directly.

**Cost:** free.

---

## D6 — Cost and waste

**Status: implemented** for duplicate-call detection and per-method cost attribution.

**Catches:** compute units burned per method, and money spent on calls that did not need to happen.

**Inputs:** `costUnits` from a provider-weighted method table (Alchemy CU, Infura credits,
QuickNode credits), plus `(method, params, blockNumber)` identity.

**Reports:**
- Cost per method, per service, per project, over time.
- **Duplicate calls:** identical `(method, params, blockNumber)` issued more than once within the
  same block. At a pinned height these are provably identical requests — the second one is a cache
  miss you paid for. This is extremely common in practice and usually invisible.
- Cost attributable to calls whose results were never used because a stale-head or disagreement
  incident invalidated them.

**Why this one earns attention:** every other detector reports correctness. This one reports a
dollar figure, and a dollar figure with a reproducible methodology behind it is what gets a project
shared. The duplicate-call number in particular tends to be embarrassingly large.

**False positives to handle:** deliberate polling of the same value across a block boundary is not
waste — scope duplicate detection strictly within one `blockNumber`.

**Cost:** free.

---

## Shipping today

These exist in `assessThreat` and fire on the current, pre-result-capture event schema.

| Signal | Condition |
|---|---|
| `provider_degradation` | Recent p95 > 500ms **and** > 3× the provider's recent baseline |
| `provider_failures` | Hard failure rate > 20% in the window |
| `rpc_flooding` | > 200 calls to one method from a single source in the window |
| `tx_burst` | Wallet ≥ 10 submissions in an hour **and** > 10× its historical baseline |
| `sensitive_rpc` | Method matches `send`/`sign`/`private`/`unlock` |

They remain useful and require no result capture, but none of them can see a provider that lies
quickly and politely. That is what D1–D6 are for.
