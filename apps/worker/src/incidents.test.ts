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
});
