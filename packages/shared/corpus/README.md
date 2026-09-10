# Normalization corpus

Real JSON-RPC responses, recorded verbatim from five public Ethereum endpoints, used by
[`src/corpus.test.ts`](../src/corpus.test.ts).

## Why it exists

Cross-provider verification ([D2](../../../docs/detectors.md#d2--cross-provider-disagreement))
is only as trustworthy as result normalization. Too weak and honest providers look like they
disagree over formatting, so every sample is a false positive. Too strong and genuinely
different answers collapse into the same hash, so real disagreement goes unreported.

Hand-written fixtures cannot settle that question, because the formatting differences that
matter are the ones nobody thinks to invent.

## How it was recorded

```bash
npm run record:corpus
```

Every call is pinned to one concrete block, 32 blocks behind the head — deep enough that no
realistic reorg can move it, shallow enough that free endpoints still hold the state. Going
further back turns every state-reading call into an archive request, which most public
endpoints refuse.

Endpoints: `publicnode`, `drpc`, `blastapi`, `onfinality`, `mevblocker`.

## What it actually shows

All five endpoints returned **semantically identical results** for all nine calls: the same
key sets, the same values. The differences are entirely in **key ordering**:

| Call | Distinct key orders across 5 endpoints |
|---|---|
| `eth_getLogs` | 4 |
| `eth_getBlockByNumber` | 2 |
| `eth_getTransactionReceipt` | 2 |

Response envelopes differ too — `{jsonrpc, result, id}` versus `{id, jsonrpc, result}` versus
`{id, result, jsonrpc}`.

So the corpus proves one thing well: **normalization collapses real key-order variance across
five independent providers**, and still separates genuinely different values.

## What it does not show

This sample did **not** contain leading-zero differences on quantities, hex-case differences,
differing log order, or differing key sets. Modern geth-family nodes agree closely on those.

That leaves those cases untested by evidence, so `corpus.test.ts` covers them separately under
`describe("derived variants")` — **synthetic mutations of the real responses**, clearly labelled
as such. The recorded corpus is evidence; the derived block is coverage. Do not confuse the two,
and do not describe the derived cases as observed provider behaviour.

## Re-recording

The fixtures are pinned to a block that free endpoints will eventually stop serving state for.
When the state-reading calls start returning archive errors, re-record. Results are expected to
change; what must not change is that every answering endpoint normalizes to one hash.
