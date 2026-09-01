import { describe, expect, it, vi } from "vitest";
import { SentinelEvent, ThreatAssessment } from "@sentinel/shared";
import { createIncidentIfNeeded, persistEvent } from "./db.js";

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
    expect(JSON.parse(params[30] as string)).toEqual(assessment.signals);
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
