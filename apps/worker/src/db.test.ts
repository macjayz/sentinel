import { describe, expect, it, vi } from "vitest";
import { SentinelEvent, ThreatAssessment } from "@sentinel/shared";
import type { AlertRule } from "./alertRules.js";
import {
  createIncidentIfNeeded,
  getProviderRpcStats,
  getWalletTransactionStats,
  getCostWasteContext,
  getDisagreementContext,
  getReorgContext,
  getSilentFailureContext,
  getStaleHeadContext,
  getThrottlingContext,
  getWeb3ThreatContext,
  persistEvent,
  raiseAlertRuleIncident
} from "./db.js";

const event: SentinelEvent = {
  id: "event-jsonb-1",
  traceId: "0123456789abcdef0123456789abcdef",
  projectId: "demo",
  serviceName: "api",
  environment: "test",
  timestamp: "2026-09-01T20:12:00.000Z",
  kind: "rest",
  request: {
    method: "POST",
    path: "/api/login",
    route: "/api/login",
    ip: "203.0.113.10",
    userAgent: "vitest",
    headers: { authorization: "[REDACTED]" },
    query: { source: "test" },
    body: { email: "owner@sentinel.local" },
    auth: { present: true, failed: true }
  },
  response: {
    statusCode: 401,
    latencyMs: 44,
    bodyBytes: 120
  }
};

const assessment: ThreatAssessment = {
  score: 25,
  severity: "medium",
  signals: [{ name: "auth_failure", weight: 24, reason: "Authentication failed or was rejected" }]
};

const pool = (query: ReturnType<typeof vi.fn>) => ({ query }) as never;

describe("worker database persistence", () => {
  it("serializes jsonb insert values before sending them to Postgres", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [], rowCount: 1 });
    const pool = { query };

    await persistEvent(pool as never, event, assessment);

    const params = query.mock.calls[0]?.[1] as unknown[];
    expect(JSON.parse(params[13] as string)).toEqual(event.request.headers);
    expect(JSON.parse(params[14] as string)).toEqual(event.request.query);
    expect(JSON.parse(params[15] as string)).toEqual(event.request.body);
    expect(JSON.parse(params[45] as string)).toEqual(assessment.signals);
  });

  it("redacts sensitive request data before storage", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [], rowCount: 1 });
    const pool = { query };
    const sensitiveEvent: SentinelEvent = {
      ...event,
      request: {
        ...event.request,
        headers: {
          authorization: "Bearer secret",
          "x-api-key": "sentinel_secret",
          "x-request-id": "request-1"
        },
        body: {
          email: "owner@sentinel.local",
          password: "secret-password",
          nested: { token: "secret-token" }
        }
      }
    };

    await persistEvent(pool as never, sensitiveEvent, assessment);

    const params = query.mock.calls[0]?.[1] as unknown[];
    expect(JSON.parse(params[13] as string)).toEqual({
      authorization: "[REDACTED]",
      "x-api-key": "[REDACTED]",
      "x-request-id": "request-1"
    });
    expect(JSON.parse(params[15] as string)).toEqual({
      email: "owner@sentinel.local",
      password: "[REDACTED]",
      nested: { token: "[REDACTED]" }
    });
  });

  it("persists captured error details when present", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [], rowCount: 1 });
    const pool = { query };
    const eventWithError: SentinelEvent = {
      ...event,
      error: { type: "TypeError", message: "Cannot read property 'email' of undefined", stack: "TypeError: ..." }
    };

    await persistEvent(pool as never, eventWithError, assessment);

    const params = query.mock.calls[0]?.[1] as unknown[];
    expect(params[40]).toBe("TypeError");
    expect(params[41]).toBe("Cannot read property 'email' of undefined");
    expect(params[42]).toBe("TypeError: ...");
  });

  it("persists captured rpc result metadata", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [], rowCount: 1 });
    const pool = { query };
    const rpcEvent: SentinelEvent = {
      ...event,
      kind: "evm_rpc",
      evmRpc: {
        method: "eth_getBalance",
        blockTag: "0x10",
        blockNumber: "16",
        blockHash: `0x${"a".repeat(64)}`,
        resultHash: "b".repeat(32),
        resultShape: "value",
        rpcErrorCode: -32000,
        rpcErrorMessage: "header not found",
        endpointHash: "c".repeat(32),
        costUnits: 19,
        resultCount: 25,
        throttled: true
      }
    };

    await persistEvent(pool as never, rpcEvent, assessment);

    const params = query.mock.calls[0]?.[1] as unknown[];
    expect(params[28]).toBe("0x10");
    expect(params[29]).toBe("16");
    expect(params[31]).toBe("b".repeat(32));
    expect(params[32]).toBe("value");
    expect(params[33]).toBe(-32000);
    expect(params[35]).toBe("c".repeat(32));
    expect(params[36]).toBe(19);
    expect(params[38]).toBe(25);
    expect(params[39]).toBe(true);
  });

  it("keeps incident time windows ordered when events arrive out of order", async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], rowCount: null })
      .mockResolvedValueOnce({ rows: [{ id: "incident-1", attacker_ips: ["203.0.113.9"] }], rowCount: 1 })
      .mockResolvedValueOnce({ rows: [], rowCount: 1 })
      .mockResolvedValueOnce({ rows: [], rowCount: null });
    const release = vi.fn();
    const pool = { connect: vi.fn().mockResolvedValue({ query, release }) };

    await createIncidentIfNeeded(pool as never, event, assessment);

    const updateSql = query.mock.calls[2]?.[0] as string;
    const updateParams = query.mock.calls[2]?.[1] as unknown[];

    expect(updateSql).toContain("started_at = least(started_at, $6)");
    expect(updateSql).toContain("last_seen_at = greatest(last_seen_at, $6)");
    expect(updateParams[5]).toBe(event.timestamp);
    expect(release).toHaveBeenCalledOnce();
  });
});

describe("web3 threat context", () => {
  it("returns zeroed wallet stats when no wallet address is present", async () => {
    const pool = { query: vi.fn() };
    const stats = await getWalletTransactionStats(pool as never, "demo", undefined);

    expect(stats).toEqual({ recentHourCount: 0, baselineHourlyAverage: 0 });
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("computes the wallet's recent count and hourly baseline from one query", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ recent_hour_count: 400, baseline_hourly_average: "0.125" }] });
    const pool = { query };

    const stats = await getWalletTransactionStats(pool as never, "demo", "0xabc");

    expect(stats).toEqual({ recentHourCount: 400, baselineHourlyAverage: 0.125 });
  });

  it("returns zeroed provider stats when no provider is present", async () => {
    const pool = { query: vi.fn() };
    const stats = await getProviderRpcStats(pool as never, "demo", undefined);

    expect(stats).toEqual({ recentP95LatencyMs: 0, baselineP95LatencyMs: 0, recentFailureRate: 0 });
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("derives the provider failure rate from recent totals and failures", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [{ recent_p95: "2400", baseline_p95: "180", recent_total: 20, recent_failures: 7 }]
    });
    const pool = { query };

    const stats = await getProviderRpcStats(pool as never, "demo", "alchemy");

    expect(stats).toEqual({ recentP95LatencyMs: 2400, baselineP95LatencyMs: 180, recentFailureRate: 0.35 });
  });

  it("ignores the failure rate when the recent sample size is too small", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [{ recent_p95: "40", baseline_p95: "38", recent_total: 1, recent_failures: 1 }]
    });
    const pool = { query };

    const stats = await getProviderRpcStats(pool as never, "demo", "alchemy");

    expect(stats.recentFailureRate).toBe(0);
  });

  it("skips web3 context queries entirely for non-rpc events", async () => {
    const pool = { query: vi.fn() };
    const context = await getWeb3ThreatContext(pool as never, event);

    expect(context).toEqual({});
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("gathers method, wallet, and provider stats for an rpc event", async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [{ count: 250 }] })
      .mockResolvedValueOnce({ rows: [{ recent_hour_count: 400, baseline_hourly_average: "0.125" }] })
      .mockResolvedValueOnce({
        rows: [{ recent_p95: "2400", baseline_p95: "180", recent_total: 20, recent_failures: 7 }]
      })
      // Remaining context queries are not what this test is asserting on; an empty result
      // keeps it from breaking every time another detector adds a lookup.
      .mockResolvedValue({ rows: [] });
    const pool = { query };

    const rpcEvent: SentinelEvent = {
      ...event,
      kind: "evm_rpc",
      evmRpc: { method: "eth_sendRawTransaction", walletAddress: "0xabc", provider: "alchemy" }
    };

    const context = await getWeb3ThreatContext(pool as never, rpcEvent);

    // The content-aware contexts come back empty: this event carries no chain id, result
    // shape or resolved block, so D1, D3 and D6 have nothing to compare against.
    expect(context).toMatchObject({
      recentMethodCallCount: 250,
      walletRecentHourTxCount: 400,
      walletBaselineHourlyTxCount: 0.125,
      providerRecentP95LatencyMs: 2400,
      providerBaselineP95LatencyMs: 180,
      providerRecentFailureRate: 0.35
    });
  });
});

describe("raiseAlertRuleIncident", () => {
  const rule: AlertRule = {
    id: "rule-1",
    project_id: "demo",
    metric: "error_rate_percent",
    threshold: 5,
    window_minutes: 5
  };

  it("creates a new incident and queues deliveries when none is open", async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] }) // begin
      .mockResolvedValueOnce({ rows: [] }) // existing open incident lookup (none)
      .mockResolvedValueOnce({ rows: [{ id: "incident-1" }] }) // insert incidents
      .mockResolvedValueOnce({ rows: [] }) // insert alert_deliveries
      .mockResolvedValueOnce({ rows: [] }); // commit
    const release = vi.fn();
    const pool = { connect: vi.fn().mockResolvedValue({ query, release }) };

    await raiseAlertRuleIncident(pool as never, rule, 12.5);

    expect(query.mock.calls[2]?.[0] as string).toContain("insert into incidents");
    expect(query.mock.calls[3]?.[0] as string).toContain("insert into alert_deliveries");
    expect(release).toHaveBeenCalledOnce();
  });

  it("updates the existing open incident instead of creating a duplicate", async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({ rows: [] }) // begin
      .mockResolvedValueOnce({ rows: [{ id: "incident-1" }] }) // existing open incident lookup (found)
      .mockResolvedValueOnce({ rows: [] }) // update incidents
      .mockResolvedValueOnce({ rows: [] }); // commit
    const release = vi.fn();
    const pool = { connect: vi.fn().mockResolvedValue({ query, release }) };

    await raiseAlertRuleIncident(pool as never, rule, 12.5);

    expect(query.mock.calls[2]?.[0] as string).toContain("update incidents");
    expect(query.mock.calls).toHaveLength(4);
  });
});

describe("stale head context", () => {
  it("does not query at all without a chain id", async () => {
    const pool = { query: vi.fn() };

    expect(await getStaleHeadContext(pool as never, "demo", undefined, "endpoint-a")).toEqual({});
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("derives how long the head has stood still from when it was first seen", async () => {
    const headSince = new Date(Date.now() - 40_000).toISOString();
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          endpoint_head: "1000",
          observations: 12,
          head_since: headSince,
          block_span: "0",
          span_seconds: "300",
          chain_head: "1010"
        }
      ]
    });

    const context = await getStaleHeadContext(pool(query), "demo", "1", "endpoint-a");

    expect(context.endpointHeadBlockNumber).toBe(1000);
    expect(context.chainHeadBlockNumber).toBe(1010);
    expect(context.endpointHeadObservations).toBe(12);
    expect(context.endpointHeadStalledMs).toBeGreaterThanOrEqual(40_000);
    // No blocks were produced across the window, so no block time can be measured.
    expect(context.measuredBlockTimeMs).toBeUndefined();
  });

  it("measures a block time when the head did advance", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          endpoint_head: "1100",
          observations: 30,
          head_since: new Date().toISOString(),
          block_span: "100",
          span_seconds: "200",
          chain_head: "1100"
        }
      ]
    });

    const context = await getStaleHeadContext(pool(query), "demo", "999", "endpoint-a");

    expect(context.measuredBlockTimeMs).toBe(2_000);
  });
});

describe("silent failure context", () => {
  const rpcEventWith = (evmRpc: Record<string, unknown>, params: unknown[] = ["0xdead"]): SentinelEvent => ({
    ...event,
    kind: "evm_rpc",
    request: { ...event.request, body: { jsonrpc: "2.0", method: "eth_getTransactionReceipt", params } },
    evmRpc: { method: "eth_getTransactionReceipt", ...evmRpc } as SentinelEvent["evmRpc"]
  });

  it("only looks for a prior success when the result actually came back null", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ max_count: 5, hits: 1 }] });
    const context = await getSilentFailureContext(
      pool(query),
      "demo",
      rpcEventWith({ resultShape: "value" })
    );

    expect(context.priorNonNullForSameTarget).toBeUndefined();
  });

  it("flags a null result the same endpoint previously answered", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ prior: true }] });
    const context = await getSilentFailureContext(
      pool(query),
      "demo",
      rpcEventWith({ resultShape: "null", endpointHash: "endpoint-a" })
    );

    expect(context.priorNonNullForSameTarget).toBe(true);
  });

  it("reads the endpoint's result ceiling when a count was captured", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ max_count: "1000", hits: 7 }] });
    const context = await getSilentFailureContext(
      pool(query),
      "demo",
      rpcEventWith({ method: "eth_getLogs", resultCount: 1000 }, [{}])
    );

    expect(context.endpointMaxResultCount).toBe(1000);
    expect(context.endpointMaxResultCountHits).toBe(7);
  });
});

describe("cost waste context", () => {
  it("does not query for calls that were never pinned to a block", async () => {
    const poolMock = { query: vi.fn() };
    const rpcEvent: SentinelEvent = {
      ...event,
      kind: "evm_rpc",
      evmRpc: { method: "eth_call" }
    };

    expect(await getCostWasteContext(poolMock as never, "demo", rpcEvent)).toEqual({});
    expect(poolMock.query).not.toHaveBeenCalled();
  });

  it("counts identical calls at the same height and what they cost", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ duplicates: 4, cost_units: 104 }] });
    const rpcEvent: SentinelEvent = {
      ...event,
      kind: "evm_rpc",
      request: {
        ...event.request,
        body: { jsonrpc: "2.0", method: "eth_call", params: [{ to: "0xabc" }, "0x10"] }
      },
      evmRpc: { method: "eth_call", blockNumber: "16" }
    };

    const context = await getCostWasteContext(pool(query), "demo", rpcEvent);

    expect(context).toEqual({ duplicateCallCount: 4, duplicateCostUnits: 104 });
  });
});

describe("disagreement context", () => {
  const shadowEvent = (evmRpc: Record<string, unknown>): SentinelEvent => ({
    ...event,
    id: "shadow-1",
    kind: "evm_rpc",
    evmRpc: {
      method: "eth_call",
      blockNumber: "1000",
      resultHash: "aaaa",
      shadowOfTraceId: "trace-1",
      ...evmRpc
    } as SentinelEvent["evmRpc"]
  });

  it("ignores events that are not verification observations", async () => {
    const poolMock = { query: vi.fn() };
    const plain: SentinelEvent = {
      ...event,
      kind: "evm_rpc",
      evmRpc: { method: "eth_call", blockNumber: "1000", resultHash: "aaaa" }
    };

    expect(await getDisagreementContext(poolMock as never, "demo", plain)).toEqual({});
    expect(poolMock.query).not.toHaveBeenCalled();
  });

  it("collects sibling hashes taken at the same pinned height", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [
        { evm_endpoint_hash: "e2", evm_provider: "infura", evm_result_hash: "bbbb", evm_result_shape: "value" }
      ]
    });

    const context = await getDisagreementContext(pool(query), "demo", shadowEvent({}));

    expect(context.peerResults).toEqual([{ endpointHash: "e2", provider: "infura", resultHash: "bbbb" }]);
    expect(context.peersMissingBlock).toBe(0);
  });

  it("counts unanswerable siblings as missing the block, not as disagreeing", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [
        { evm_endpoint_hash: "e2", evm_provider: "infura", evm_result_hash: null, evm_result_shape: "null" },
        {
          evm_endpoint_hash: "e3",
          evm_provider: "quicknode",
          evm_result_hash: null,
          evm_result_shape: "error_in_body"
        }
      ]
    });

    const context = await getDisagreementContext(pool(query), "demo", shadowEvent({}));

    expect(context.peerResults).toEqual([]);
    expect(context.peersMissingBlock).toBe(2);
  });
});

describe("reorg context", () => {
  const hashA = `0x${"a".repeat(64)}`;
  const hashB = `0x${"b".repeat(64)}`;

  const blockEvent = (evmRpc: Record<string, unknown> = {}): SentinelEvent => ({
    ...event,
    kind: "evm_rpc",
    evmRpc: {
      method: "eth_getBlockByNumber",
      chainId: "1",
      blockNumber: "1000",
      blockHash: hashA,
      endpointHash: "e1",
      ...evmRpc
    } as SentinelEvent["evmRpc"]
  });

  it("says nothing without a block hash to compare", async () => {
    const poolMock = { query: vi.fn() };

    expect(await getReorgContext(poolMock as never, "demo", blockEvent({ blockHash: undefined }))).toEqual({});
    expect(poolMock.query).not.toHaveBeenCalled();
  });

  it("reports a hash that was replaced and how deep the rewrite went", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [{ prior_hash: hashB, peer_moved_on_at: null, reorg_depth: 3 }]
    });

    const context = await getReorgContext(pool(query), "demo", blockEvent());

    expect(context.priorBlockHashAtHeight).toBe(hashB);
    expect(context.reorgDepth).toBe(3);
    expect(context.supersededByPeer).toBe(false);
  });

  it("measures how long peers have been on a different chain", async () => {
    const movedOn = new Date(Date.now() - 20_000).toISOString();
    const query = vi.fn().mockResolvedValue({
      rows: [{ prior_hash: null, peer_moved_on_at: movedOn, reorg_depth: 1 }]
    });

    const context = await getReorgContext(pool(query), "demo", blockEvent());

    expect(context.supersededByPeer).toBe(true);
    expect(context.peerConvergenceLagMs).toBeGreaterThanOrEqual(20_000);
  });
});

describe("throttling context", () => {
  it("derives throttle and degradation rates from one query", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          recent_total: 100,
          recent_throttled: 12,
          recent_shaped: 80,
          recent_degraded: 32,
          baseline_shaped: 1000,
          baseline_degraded: 50
        }
      ]
    });

    const context = await getThrottlingContext(pool(query), "demo", "endpoint-a");

    expect(context.recentRequestCount).toBe(100);
    expect(context.recentThrottleRate).toBeCloseTo(0.12);
    expect(context.recentDegradedResultRate).toBeCloseTo(0.4);
    expect(context.baselineDegradedResultRate).toBeCloseTo(0.05);
  });

  it("measures degradation only over events that carry a result shape", async () => {
    // 100 recent requests but only 10 captured a shape; 5 of those were degraded. The
    // rate is 50%, not 5% — older uncaptured traffic must not dilute it.
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          recent_total: 100,
          recent_throttled: 0,
          recent_shaped: 10,
          recent_degraded: 5,
          baseline_shaped: 0,
          baseline_degraded: 0
        }
      ]
    });

    const context = await getThrottlingContext(pool(query), "demo", "endpoint-a");

    expect(context.recentDegradedResultRate).toBeCloseTo(0.5);
    expect(context.baselineDegradedResultRate).toBe(0);
  });

  it("returns zeroed rates rather than dividing by zero on a quiet endpoint", async () => {
    const query = vi.fn().mockResolvedValue({
      rows: [
        {
          recent_total: 0,
          recent_throttled: 0,
          recent_shaped: 0,
          recent_degraded: 0,
          baseline_shaped: 0,
          baseline_degraded: 0
        }
      ]
    });

    const context = await getThrottlingContext(pool(query), "demo", undefined);

    expect(context).toEqual({
      recentRequestCount: 0,
      recentThrottleRate: 0,
      recentDegradedResultRate: 0,
      baselineDegradedResultRate: 0
    });
  });
});
