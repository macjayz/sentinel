import { describe, expect, it } from "vitest";
import {
  assessThreat,
  classifyTraffic,
  normalizeErrorMessage,
  normalizeRoutePath,
  redactHeaders,
  redactValue,
  SentinelEvent
} from "./index.js";

describe("shared security helpers", () => {
  it("redacts nested sensitive values", () => {
    expect(redactValue({ user: { password: "secret" }, token: "abc" })).toEqual({
      user: { password: "[REDACTED]" },
      token: "[REDACTED]"
    });
  });

  it("redacts sensitive headers case-insensitively", () => {
    expect(redactHeaders({ Authorization: "Bearer x", "x-request-id": "1" })).toEqual({
      Authorization: "[REDACTED]",
      "x-request-id": "1"
    });
  });

  it("classifies graphql and evm traffic", () => {
    expect(classifyTraffic("/graphql", {})).toBe("graphql");
    expect(classifyTraffic("/rpc", { jsonrpc: "2.0", method: "eth_sendRawTransaction" })).toBe(
      "evm_rpc"
    );
  });

  it("normalizes noisy route parameters", () => {
    expect(normalizeRoutePath("/users/283/orders/550e8400-e29b-41d4-a716-446655440000")).toBe(
      "/users/:id/orders/:uuid"
    );
    expect(normalizeRoutePath("/wallets/0x742d35Cc6634C0532925a3b844Bc454e4438f44e")).toBe(
      "/wallets/:address"
    );
  });

  it("normalizes dynamic ids out of error messages so similar errors group together", () => {
    expect(normalizeErrorMessage("Cannot find user 4821")).toBe("Cannot find user #");
    expect(normalizeErrorMessage("Cannot find user 4822")).toBe("Cannot find user #");
    expect(normalizeErrorMessage("Order 550e8400-e29b-41d4-a716-446655440000 not found")).toBe(
      "Order :uuid not found"
    );
    expect(normalizeErrorMessage("Cannot read property 'email' of undefined")).toBe(
      "Cannot read property 'email' of undefined"
    );
  });

  it("scores high-risk rpc requests", () => {
    const event: SentinelEvent = {
      id: "event-123",
      traceId: "0123456789abcdef0123456789abcdef",
      projectId: "project",
      serviceName: "api",
      environment: "test",
      timestamp: new Date().toISOString(),
      kind: "evm_rpc",
      request: {
        method: "POST",
        path: "/rpc",
        headers: {},
        query: {},
        auth: { present: true, failed: true }
      },
      response: { statusCode: 401, latencyMs: 40 },
      evmRpc: { method: "eth_sendRawTransaction" }
    };

    expect(assessThreat(event, 130).severity).toBe("critical");
  });

  const rpcEvent: SentinelEvent = {
    id: "event-rpc-1",
    projectId: "project",
    serviceName: "web3-rpc",
    environment: "test",
    timestamp: new Date().toISOString(),
    kind: "evm_rpc",
    request: {
      method: "POST",
      path: "/rpc",
      ip: "203.0.113.50",
      headers: {},
      query: {},
      auth: { present: true, failed: false }
    },
    response: { statusCode: 200, latencyMs: 60 },
    evmRpc: { method: "eth_getLogs", provider: "alchemy" }
  };

  it("flags rpc flooding when a method is called far more than normal", () => {
    const assessment = assessThreat(rpcEvent, 0, { recentMethodCallCount: 250 });
    expect(assessment.signals.map((signal) => signal.name)).toContain("rpc_flooding");
  });

  it("does not flag rpc flooding under the threshold", () => {
    const assessment = assessThreat(rpcEvent, 0, { recentMethodCallCount: 50 });
    expect(assessment.signals.map((signal) => signal.name)).not.toContain("rpc_flooding");
  });

  it("flags a transaction burst against a wallet's baseline", () => {
    const txEvent: SentinelEvent = {
      ...rpcEvent,
      evmRpc: { method: "eth_sendRawTransaction", walletAddress: "0xabc" }
    };

    const assessment = assessThreat(txEvent, 0, {
      walletRecentHourTxCount: 400,
      walletBaselineHourlyTxCount: 0.125
    });

    expect(assessment.signals.map((signal) => signal.name)).toContain("tx_burst");
  });

  it("does not flag a transaction burst within normal wallet activity", () => {
    const txEvent: SentinelEvent = {
      ...rpcEvent,
      evmRpc: { method: "eth_sendRawTransaction", walletAddress: "0xabc" }
    };

    const assessment = assessThreat(txEvent, 0, {
      walletRecentHourTxCount: 5,
      walletBaselineHourlyTxCount: 0.5
    });

    expect(assessment.signals.map((signal) => signal.name)).not.toContain("tx_burst");
  });

  it("flags provider latency degradation against its own baseline", () => {
    const assessment = assessThreat(rpcEvent, 0, {
      providerRecentP95LatencyMs: 2400,
      providerBaselineP95LatencyMs: 180
    });

    expect(assessment.signals.map((signal) => signal.name)).toContain("provider_degradation");
  });

  it("does not flag provider degradation when latency is stable", () => {
    const assessment = assessThreat(rpcEvent, 0, {
      providerRecentP95LatencyMs: 200,
      providerBaselineP95LatencyMs: 180
    });

    expect(assessment.signals.map((signal) => signal.name)).not.toContain("provider_degradation");
  });

  it("flags an elevated rpc provider failure rate", () => {
    const assessment = assessThreat(rpcEvent, 0, { providerRecentFailureRate: 0.35 });
    expect(assessment.signals.map((signal) => signal.name)).toContain("provider_failures");
  });

  it("does not flag a normal rpc provider failure rate", () => {
    const assessment = assessThreat(rpcEvent, 0, { providerRecentFailureRate: 0.05 });
    expect(assessment.signals.map((signal) => signal.name)).not.toContain("provider_failures");
  });
});
