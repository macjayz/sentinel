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
| `resultShape` | `null` \| `empty_array` \| `value` \| `error_in_body` | Cheap silent-failure signal |
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
  not a global constant. Ship the table for mainnet, Base, Arbitrum, Optimism, Polygon; fall back to
  measured median block time for unknown chains.
- A deliberately `finalized`-tagged call is *supposed* to lag. Exclude non-`latest` tags.

**Cost:** free. Derived entirely from calls the application already makes.

---

## D2 — Cross-provider disagreement

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
- One provider not yet having the block — treat "block not found at pinned height" as a D1 stale-head
  observation, not a disagreement.
- Non-deterministic methods (`eth_gasPrice`, `eth_estimateGas`, anything `pending`) must never be
  shadowed. Enforce with an allowlist, not a denylist.

**Cost:** `shadowSampleRate × secondaryCount` extra calls, on endpoints you configure. Must be
budgeted with a hard ceiling (`maxShadowCallsPerMinute`) so verification can never become the
dominant cost. Default the ceiling low and make it explicit in config.

---

## D3 — Silent failure

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
- Known provider page limits need a maintained table; when unknown, learn the modal result count per
  endpoint and treat a hard ceiling as suspicious.

**Cost:** free for the in-body checks; the comparative checks ride on D2's samples.

---

## D4 — Reorg lag

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
- A one-block reorg on mainnet is normal and should be recorded as data, not raised as an incident.
  Alert on depth ≥ 2, or on convergence lag above a threshold.
- Uncle/ommer blocks on some chains will look like reorgs; scope the tracker to canonical-chain
  responses only.

**Cost:** free. Derived from block hashes already present in responses.

---

## D5 — Throttling as success

**Catches:** rate limiting that does not arrive as a clean `429`.

**Inputs:** status codes, provider-specific throttle error codes, latency distribution, and D3's
result-shape signals.

**Fires when:**
- Explicit throttle responses exceed `throttleRateThreshold` of requests in the window, or
- A latency cliff (p95 stepping above `3×` baseline) coincides with a rise in empty or truncated
  results — the signature of soft throttling.

**False positives to handle:** a latency cliff alone is already covered by the shipping
`provider_degradation` signal. D5 should only fire when latency degradation *and* result
degradation appear together; otherwise defer to the existing signal.

**Cost:** free.

---

## D6 — Cost and waste

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
