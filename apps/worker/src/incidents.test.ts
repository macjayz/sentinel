import { describe, expect, it } from "vitest";
import { SentinelEvent } from "@sentinel/shared";
import { fingerprintIncident } from "./incidents.js";

const baseEvent: SentinelEvent = {
  id: "event-1",
  projectId: "demo",
  serviceName: "api",
  environment: "test",
  timestamp: new Date().toISOString(),
  kind: "rest",
  request: {
    method: "POST",
    path: "/api/login",
    route: "/api/login",
    ip: "203.0.113.14",
    headers: {},
    query: {},
    auth: { present: true, failed: true }
  },
  response: {
    statusCode: 401,
    latencyMs: 40
  }
};

describe("incident fingerprinting", () => {
  it("groups auth failures by project and endpoint", () => {
    const fingerprint = fingerprintIncident(baseEvent, {
      score: 54,
      severity: "high",
      signals: [{ name: "auth_failure", weight: 24, reason: "Authentication failed" }]
    });

    expect(fingerprint?.key).toBe("demo:credential_stuffing:POST /api/login");
    expect(fingerprint?.affectedEndpoint).toBe("POST /api/login");
  });

  it("ignores low risk events", () => {
    expect(fingerprintIncident(baseEvent, { score: 10, severity: "low", signals: [] })).toBeNull();
  });

  const rpcEvent: SentinelEvent = {
    ...baseEvent,
    kind: "evm_rpc",
    request: { ...baseEvent.request, path: "/rpc", route: "/rpc" },
    evmRpc: { method: "eth_getLogs", provider: "alchemy" }
  };

  it("groups rpc flooding by project and method", () => {
    const fingerprint = fingerprintIncident(rpcEvent, {
      score: 53,
      severity: "high",
      signals: [{ name: "rpc_flooding", weight: 28, reason: "Called too often" }]
    });

    expect(fingerprint?.key).toBe("demo:rpc_flooding:eth_getLogs");
  });

  it("prefers the rpc-specific category over the generic rate anomaly for the same flood", () => {
    // A flood of calls to one method from one IP always also trips the generic per-IP rate
    // check, since it's a strict subset of "all requests from this IP". The more specific
    // category should win the incident title.
    const fingerprint = fingerprintIncident(rpcEvent, {
      score: 58,
      severity: "high",
      signals: [
        { name: "rate_anomaly", weight: 30, reason: "IP exceeded normal request volume" },
        { name: "rpc_flooding", weight: 28, reason: "Called too often" }
      ]
    });

    expect(fingerprint?.key).toBe("demo:rpc_flooding:eth_getLogs");
  });

  it("groups transaction bursts by wallet address", () => {
    const txEvent: SentinelEvent = {
      ...rpcEvent,
      evmRpc: { method: "eth_sendRawTransaction", walletAddress: "0x1234567890abcdef" }
    };

    const fingerprint = fingerprintIncident(txEvent, {
      score: 55,
      severity: "high",
      signals: [{ name: "tx_burst", weight: 30, reason: "Spiked above baseline" }]
    });

    expect(fingerprint?.key).toBe("demo:tx_burst:0x1234567890abcdef");
    expect(fingerprint?.title).toContain("0x1234...cdef");
  });

  it("groups provider degradation by provider name", () => {
    const fingerprint = fingerprintIncident(rpcEvent, {
      score: 45,
      severity: "medium",
      signals: [{ name: "provider_degradation", weight: 20, reason: "Latency degraded" }]
    });

    expect(fingerprint?.key).toBe("demo:provider_degradation:alchemy");
  });

  it("groups provider failures by provider name", () => {
    const fingerprint = fingerprintIncident(rpcEvent, {
      score: 47,
      severity: "medium",
      signals: [{ name: "provider_failures", weight: 22, reason: "Elevated failures" }]
    });

    expect(fingerprint?.key).toBe("demo:provider_failures:alchemy");
  });
});
