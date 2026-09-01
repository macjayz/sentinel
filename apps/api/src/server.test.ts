import { describe, expect, it, vi } from "vitest";
import { buildServer } from "./server.js";

vi.mock("./db.js", () => ({
  createPool: () => ({ end: vi.fn() }),
  getOverview: () => ({ totals: { events: 0, openIncidents: 0, averageLatencyMs: 0 }, endpoints: [], ips: [] }),
  getIncidents: () => [],
  getRequests: () => []
}));

vi.mock("./queue.js", () => ({
  createRedis: () => ({ quit: vi.fn(), pipeline: vi.fn() }),
  enqueueEvents: vi.fn()
}));

describe("api server", () => {
  it("rejects event ingestion without an api key", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "POST",
      url: "/v1/events",
      payload: { events: [] }
    });

    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it("exposes health without authentication", async () => {
    const { app } = await buildServer();
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.statusCode).toBe(200);
    await app.close();
  });

  it("adds request ids to responses", async () => {
    const { app } = await buildServer();
    const response = await app.inject({ method: "GET", url: "/health" });

    expect(response.headers["x-request-id"]).toBeTypeOf("string");
    await app.close();
  });

  it("exposes request explorer data without sdk authentication", async () => {
    const { app } = await buildServer();
    const response = await app.inject({ method: "GET", url: "/v1/analytics/requests?limit=10" });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual([]);
    await app.close();
  });
});
