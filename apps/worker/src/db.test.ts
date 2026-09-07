import { describe, expect, it, vi } from "vitest";
import { SentinelEvent, ThreatAssessment } from "@sentinel/shared";
import type { AlertRule } from "./alertRules.js";
import {
  createIncidentIfNeeded,
  getProviderRpcStats,
  getWalletTransactionStats,
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

describe("worker database persistence", () => {
  it("serializes jsonb insert values before sending them to Postgres", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [], rowCount: 1 });
    const pool = { query };

    await persistEvent(pool as never, event, assessment);

    const params = query.mock.calls[0]?.[1] as unknown[];
    expect(JSON.parse(params[13] as string)).toEqual(event.request.headers);
    expect(JSON.parse(params[14] as string)).toEqual(event.request.query);
    expect(JSON.parse(params[15] as string)).toEqual(event.request.body);
    expect(JSON.parse(params[33] as string)).toEqual(assessment.signals);
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
    expect(params[28]).toBe("TypeError");
    expect(params[29]).toBe("Cannot read property 'email' of undefined");
    expect(params[30]).toBe("TypeError: ...");
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
      });
    const pool = { query };

    const rpcEvent: SentinelEvent = {
      ...event,
      kind: "evm_rpc",
      evmRpc: { method: "eth_sendRawTransaction", walletAddress: "0xabc", provider: "alchemy" }
    };

    const context = await getWeb3ThreatContext(pool as never, rpcEvent);

    expect(context).toEqual({
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
