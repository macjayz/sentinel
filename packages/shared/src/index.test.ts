import { describe, expect, it } from "vitest";
import {
  assessThreat,
  classifyTraffic,
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
});
