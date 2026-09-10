import { describe, expect, it } from "vitest";
import { assessThreat, type SentinelEvent } from "./index.js";
import {
  detectCostWaste,
  detectDisagreement,
  detectReorgLag,
  detectSilentFailure,
  detectStaleHead,
  detectThrottling
} from "./detectors.js";

function rpcEvent(evmRpc: Partial<NonNullable<SentinelEvent["evmRpc"]>> = {}): SentinelEvent {
  return {
    id: "event-detector-1",
    projectId: "demo",
    serviceName: "web3-rpc",
    environment: "test",
    timestamp: "2026-09-09T10:00:00.000Z",
    kind: "evm_rpc",
    request: {
      method: "POST",
      path: "/rpc",
      headers: {},
      query: {},
      auth: { present: true, failed: false }
    },
    response: { statusCode: 200, latencyMs: 40 },
    evmRpc: { method: "eth_getBalance", chainId: "1", ...evmRpc }
  };
}

const names = (signals: { name: string }[]) => signals.map((signal) => signal.name);

describe("D1 stale head", () => {
  const observed = { endpointHeadObservations: 5 };

  it("does not judge an endpoint on too few observations", () => {
    const signals = detectStaleHead(rpcEvent(), {
      endpointHeadObservations: 2,
      endpointHeadStalledMs: 600_000,
      endpointHeadBlockNumber: 100,
      chainHeadBlockNumber: 500
    });

    expect(signals).toEqual([]);
  });

  it("ignores calls that are supposed to lag", () => {
    for (const blockTag of ["finalized", "safe", "earliest"]) {
      const signals = detectStaleHead(rpcEvent({ blockTag }), {
        ...observed,
        endpointHeadStalledMs: 600_000
      });
      expect(signals, blockTag).toEqual([]);
    }
  });

  it("ignores calls pinned to a past block", () => {
    const signals = detectStaleHead(rpcEvent({ blockTag: "0x10" }), {
      ...observed,
      endpointHeadStalledMs: 600_000
    });

    expect(signals).toEqual([]);
  });

  it("fires when a head stops advancing while the provider keeps answering", () => {
    // Mainnet block time is 12s, so the default 3x multiplier allows 36s.
    const signals = detectStaleHead(rpcEvent(), { ...observed, endpointHeadStalledMs: 40_000 });

    expect(names(signals)).toContain("stale_head_stalled");
    expect(signals[0].reason).toContain("40s");
  });

  it("stays quiet while the head is merely slow", () => {
    const signals = detectStaleHead(rpcEvent(), { ...observed, endpointHeadStalledMs: 30_000 });

    expect(names(signals)).not.toContain("stale_head_stalled");
  });

  it("fires when a head trails the furthest-ahead endpoint", () => {
    const signals = detectStaleHead(rpcEvent(), {
      ...observed,
      endpointHeadBlockNumber: 1_000,
      chainHeadBlockNumber: 1_010
    });

    expect(names(signals)).toContain("stale_head_lagging");
    expect(signals[0].reason).toContain("10 blocks behind");
  });

  it("tolerates lag within the allowed margin", () => {
    const signals = detectStaleHead(rpcEvent(), {
      ...observed,
      endpointHeadBlockNumber: 1_000,
      chainHeadBlockNumber: 1_003
    });

    expect(names(signals)).not.toContain("stale_head_lagging");
  });

  it("falls back to a measured block time on an unknown chain", () => {
    const event = rpcEvent({ chainId: "999999" });

    expect(names(detectStaleHead(event, { ...observed, endpointHeadStalledMs: 5_000 }))).toEqual([]);
    expect(
      names(
        detectStaleHead(event, {
          ...observed,
          endpointHeadStalledMs: 5_000,
          measuredBlockTimeMs: 1_000
        })
      )
    ).toContain("stale_head_stalled");
  });
});

describe("D3 silent failure", () => {
  it("reports a JSON-RPC error carried inside a success response", () => {
    const signals = detectSilentFailure(
      rpcEvent({ method: "eth_call", resultShape: "error_in_body", rpcErrorCode: -32000 })
    );

    expect(names(signals)).toContain("rpc_error_in_body");
    expect(signals[0].reason).toContain("code -32000");
  });

  it("reports a receipt that disappeared after being reported as mined", () => {
    const event = rpcEvent({ method: "eth_getTransactionReceipt", resultShape: "null" });
    const signals = detectSilentFailure(event, { priorNonNullForSameTarget: true });

    expect(names(signals)).toContain("receipt_disappeared");
  });

  it("stays quiet on a null receipt with no prior success", () => {
    // A pending or unknown transaction legitimately has no receipt.
    const event = rpcEvent({ method: "eth_getTransactionReceipt", resultShape: "null" });

    expect(detectSilentFailure(event, {})).toEqual([]);
  });

  it("reports empty call data only when the same call previously returned data", () => {
    const event = rpcEvent({ method: "eth_call", resultShape: "empty_data" });

    expect(detectSilentFailure(event, {})).toEqual([]);
    expect(names(detectSilentFailure(event, { priorDataForSameCall: true }))).toContain(
      "empty_data_regression"
    );
  });

  it("reports a repeated result ceiling as suspected truncation", () => {
    const event = rpcEvent({ method: "eth_getLogs", resultCount: 1000 });
    const signals = detectSilentFailure(event, {
      endpointMaxResultCount: 1000,
      endpointMaxResultCountHits: 4
    });

    expect(names(signals)).toContain("suspected_log_truncation");
    expect(signals[0].reason).toContain("1000");
  });

  it("does not call a one-off maximum a page limit", () => {
    const event = rpcEvent({ method: "eth_getLogs", resultCount: 1000 });
    const signals = detectSilentFailure(event, {
      endpointMaxResultCount: 1000,
      endpointMaxResultCountHits: 1
    });

    expect(signals).toEqual([]);
  });

  it("never treats an empty log range as truncation", () => {
    const event = rpcEvent({ method: "eth_getLogs", resultCount: 0 });
    const signals = detectSilentFailure(event, {
      endpointMaxResultCount: 0,
      endpointMaxResultCountHits: 9
    });

    expect(signals).toEqual([]);
  });
});

describe("D6 cost and waste", () => {
  it("reports an identical call already made at the same height", () => {
    const event = rpcEvent({ method: "eth_call", blockNumber: "1000" });
    const signals = detectCostWaste(event, { duplicateCallCount: 3, duplicateCostUnits: 78 });

    expect(names(signals)).toEqual(["duplicate_rpc_call"]);
    expect(signals[0].reason).toContain("78 compute units");
  });

  it("carries no weight, because waste is not a threat", () => {
    const event = rpcEvent({ method: "eth_call", blockNumber: "1000" });
    const signals = detectCostWaste(event, { duplicateCallCount: 2 });

    expect(signals[0].weight).toBe(0);
  });

  it("does not claim waste for calls that were never pinned to a height", () => {
    const event = rpcEvent({ method: "eth_call" });

    expect(detectCostWaste(event, { duplicateCallCount: 5 })).toEqual([]);
  });

  it("stays quiet with no duplicates", () => {
    const event = rpcEvent({ method: "eth_call", blockNumber: "1000" });

    expect(detectCostWaste(event, { duplicateCallCount: 0 })).toEqual([]);
  });
});

describe("detectors inside assessThreat", () => {
  it("surfaces content-aware signals alongside the existing ones", () => {
    const event = rpcEvent({ method: "eth_call", resultShape: "error_in_body", rpcErrorCode: -32000 });
    const assessment = assessThreat(event, 0, { silentFailure: {} });

    expect(names(assessment.signals)).toContain("rpc_error_in_body");
    expect(assessment.score).toBeGreaterThan(0);
  });

  it("lets cost waste be recorded without inflating the threat score", () => {
    const event = rpcEvent({ method: "eth_call", blockNumber: "1000" });
    const assessment = assessThreat(event, 0, { costWaste: { duplicateCallCount: 4 } });

    expect(names(assessment.signals)).toEqual(["duplicate_rpc_call"]);
    expect(assessment.score).toBe(0);
    expect(assessment.severity).toBe("low");
  });

  it("produces no content-aware signals for events that predate result capture", () => {
    const assessment = assessThreat(rpcEvent(), 0, {});

    expect(assessment.signals).toEqual([]);
  });
});

describe("D2 cross-provider disagreement", () => {
  const pinned = { method: "eth_call", blockNumber: "1000", resultHash: "aaaa" };

  it("reports peers that returned a different result at the same height", () => {
    const signals = detectDisagreement(rpcEvent(pinned), {
      peerResults: [
        { provider: "infura", resultHash: "bbbb" },
        { provider: "quicknode", resultHash: "aaaa" }
      ]
    });

    expect(names(signals)).toEqual(["provider_disagreement"]);
    expect(signals[0].reason).toContain("infura");
    expect(signals[0].reason).not.toContain("quicknode");
    expect(signals[0].weight).toBe(40);
  });

  it("stays quiet when every peer agrees", () => {
    const signals = detectDisagreement(rpcEvent(pinned), {
      peerResults: [
        { provider: "infura", resultHash: "aaaa" },
        { provider: "quicknode", resultHash: "aaaa" }
      ]
    });

    expect(signals).toEqual([]);
  });

  it("refuses to judge a call that was never pinned to a height", () => {
    // Comparing two `latest` responses measures head skew, not disagreement.
    const signals = detectDisagreement(rpcEvent({ method: "eth_call", resultHash: "aaaa" }), {
      peerResults: [{ provider: "infura", resultHash: "bbbb" }]
    });

    expect(signals).toEqual([]);
  });

  it("does not treat a peer that lacks the block as a disagreement", () => {
    const signals = detectDisagreement(rpcEvent(pinned), { peersMissingBlock: 2, peerResults: [] });

    expect(signals).toEqual([]);
  });

  it("classifies a differing log range as truncation rather than a wrong answer", () => {
    const signals = detectDisagreement(
      rpcEvent({ method: "eth_getLogs", blockNumber: "1000", resultHash: "aaaa" }),
      { peerResults: [{ provider: "infura", resultHash: "bbbb" }] }
    );

    expect(names(signals)).toEqual(["log_range_disagreement"]);
    expect(signals[0].reason).toContain("truncated");
    expect(signals[0].weight).toBeLessThan(40);
  });
});

describe("D4 reorg lag", () => {
  const hashA = `0x${"a".repeat(64)}`;
  const hashB = `0x${"b".repeat(64)}`;
  const reorged = { blockNumber: "1000", blockHash: hashB };

  it("records a single-block reorg without raising it", () => {
    const signals = detectReorgLag(rpcEvent(reorged), {
      priorBlockHashAtHeight: hashA,
      reorgDepth: 1
    });

    expect(names(signals)).toEqual(["reorg_detected"]);
    // Single-block reorgs are ordinary chain behaviour, so this must not create an incident.
    expect(signals[0].weight).toBe(0);
  });

  it("raises a deeper reorg", () => {
    const signals = detectReorgLag(rpcEvent(reorged), {
      priorBlockHashAtHeight: hashA,
      reorgDepth: 3
    });

    expect(signals[0].weight).toBe(24);
    expect(signals[0].reason).toContain("3-block reorg");
  });

  it("stays quiet when the hash at a height has not changed", () => {
    const signals = detectReorgLag(rpcEvent({ blockNumber: "1000", blockHash: hashA }), {
      priorBlockHashAtHeight: hashA,
      reorgDepth: 4
    });

    expect(signals).toEqual([]);
  });

  it("reports an endpoint still serving a chain its peers abandoned", () => {
    const signals = detectReorgLag(rpcEvent({ blockNumber: "1000", blockHash: hashA }), {
      supersededByPeer: true,
      peerConvergenceLagMs: 15_000
    });

    expect(names(signals)).toContain("reorg_lag");
    expect(signals[0].reason).toContain("15s ago");
  });

  it("tolerates brief propagation delay", () => {
    const signals = detectReorgLag(rpcEvent({ blockNumber: "1000", blockHash: hashA }), {
      supersededByPeer: true,
      peerConvergenceLagMs: 2_000
    });

    expect(signals).toEqual([]);
  });

  it("needs a block hash to say anything at all", () => {
    expect(detectReorgLag(rpcEvent({ blockNumber: "1000" }), { priorBlockHashAtHeight: hashA })).toEqual([]);
  });
});

describe("D5 throttling as success", () => {
  const sampled = { recentRequestCount: 100 };

  it("refuses to judge an endpoint on too small a sample", () => {
    const signals = detectThrottling(rpcEvent(), {
      recentRequestCount: 5,
      recentThrottleRate: 1
    });

    expect(signals).toEqual([]);
  });

  it("reports explicit rate limiting", () => {
    const signals = detectThrottling(rpcEvent(), { ...sampled, recentThrottleRate: 0.2 });

    expect(names(signals)).toEqual(["provider_throttling"]);
    expect(signals[0].reason).toContain("20%");
  });

  it("tolerates the occasional throttled request", () => {
    const signals = detectThrottling(rpcEvent(), { ...sampled, recentThrottleRate: 0.02 });

    expect(signals).toEqual([]);
  });

  it("reports soft throttling when latency and result quality degrade together", () => {
    const signals = detectThrottling(rpcEvent(), {
      ...sampled,
      recentP95LatencyMs: 2_000,
      baselineP95LatencyMs: 200,
      recentDegradedResultRate: 0.4,
      baselineDegradedResultRate: 0.05
    });

    expect(names(signals)).toEqual(["soft_throttling"]);
    expect(signals[0].reason).toContain("2000ms");
    expect(signals[0].reason).toContain("40%");
  });

  it("stays quiet on a latency cliff alone", () => {
    // provider_degradation already reports this; restating it under a second name
    // would just double-count the same finding.
    const signals = detectThrottling(rpcEvent(), {
      ...sampled,
      recentP95LatencyMs: 2_000,
      baselineP95LatencyMs: 200,
      recentDegradedResultRate: 0.05,
      baselineDegradedResultRate: 0.05
    });

    expect(signals).toEqual([]);
  });

  it("stays quiet on degraded results alone", () => {
    const signals = detectThrottling(rpcEvent(), {
      ...sampled,
      recentP95LatencyMs: 210,
      baselineP95LatencyMs: 200,
      recentDegradedResultRate: 0.4,
      baselineDegradedResultRate: 0.05
    });

    expect(signals).toEqual([]);
  });

  it("prefers the explicit finding over the inferred one", () => {
    const signals = detectThrottling(rpcEvent(), {
      ...sampled,
      recentThrottleRate: 0.3,
      recentP95LatencyMs: 2_000,
      baselineP95LatencyMs: 200,
      recentDegradedResultRate: 0.4,
      baselineDegradedResultRate: 0.05
    });

    expect(names(signals)).toEqual(["provider_throttling"]);
  });

  it("needs a baseline before calling anything a cliff", () => {
    const signals = detectThrottling(rpcEvent(), {
      ...sampled,
      recentP95LatencyMs: 2_000,
      baselineP95LatencyMs: 0,
      recentDegradedResultRate: 0.4,
      baselineDegradedResultRate: 0
    });

    expect(signals).toEqual([]);
  });
});
