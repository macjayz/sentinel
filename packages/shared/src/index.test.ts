import { describe, expect, it } from "vitest";
import { assessThreat, classifyTraffic, redactHeaders, redactValue, SentinelEvent } from "./index.js";

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

  it("scores high-risk rpc requests", () => {
    const event: SentinelEvent = {
      id: "event-123",
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
});
