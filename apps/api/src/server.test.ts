import { beforeEach, describe, expect, it, vi } from "vitest";
import { buildServer } from "./server.js";

const dbMocks = vi.hoisted(() => ({
  getRequests: vi.fn(() => []),
  getOverview: vi.fn(() => ({
    totals: { events: 0, openIncidents: 0, averageLatencyMs: 0 },
    endpoints: [],
    ips: []
  })),
  listApiKeys: vi.fn(() => []),
  createApiKey: vi.fn(() => ({
    id: "key-1",
    name: "Production SDK",
    prefix: "sentinel_test",
    key: "sentinel_test_secret",
    created_at: new Date().toISOString(),
    revoked_at: null,
    last_used_at: null
  })),
  revokeApiKey: vi.fn(() => true)
}));

vi.mock("./db.js", () => ({
  createApiKey: dbMocks.createApiKey,
  createPool: () => ({ end: vi.fn() }),
  getOverview: dbMocks.getOverview,
  getIncidents: () => [],
  getRequests: dbMocks.getRequests,
  listApiKeys: dbMocks.listApiKeys,
  revokeApiKey: dbMocks.revokeApiKey,
  resolveProjectForApiKey: (_pool: unknown, apiKey: string) =>
    apiKey === "dev-sentinel-key" ? { projectId: "demo", keyId: "test" } : null
}));

vi.mock("./queue.js", () => ({
  createRedis: () => ({ quit: vi.fn(), pipeline: vi.fn() }),
  enqueueEvents: vi.fn()
}));

describe("api server", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

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

  it("rejects event batches outside the api key project scope", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "POST",
      url: "/v1/events",
      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
      payload: {
        events: [
          {
            id: "event-123",
            projectId: "other",
            serviceName: "api",
            environment: "test",
            timestamp: new Date().toISOString(),
            kind: "rest",
            request: {
              method: "GET",
              path: "/health",
              headers: {},
              query: {},
              auth: { present: false, failed: false }
            },
            response: { statusCode: 200, latencyMs: 1 }
          }
        ]
      }
    });

    expect(response.statusCode).toBe(403);
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

  it("keeps anonymous analytics scoped to the demo project", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "GET",
      url: "/v1/analytics/requests?projectId=other&limit=10"
    });

    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual([]);
    expect(dbMocks.getRequests).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ projectId: "demo" }));
    await app.close();
  });

  it("rejects analytics requests with invalid api keys", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "GET",
      url: "/v1/analytics/overview",
      headers: { "x-sentinel-api-key": "invalid" }
    });

    expect(response.statusCode).toBe(401);
    await app.close();
  });

  it("creates project-scoped api keys", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "POST",
      url: "/v1/api-keys",
      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
      payload: { name: "Production SDK" }
    });

    expect(response.statusCode).toBe(201);
    expect(response.json().key).toBe("sentinel_test_secret");
    expect(dbMocks.createApiKey).toHaveBeenCalledWith(expect.anything(), "demo", "Production SDK");
    await app.close();
  });

  it("revokes project-scoped api keys", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "DELETE",
      url: "/v1/api-keys/key-1",
      headers: { "x-sentinel-api-key": "dev-sentinel-key" }
    });

    expect(response.statusCode).toBe(204);
    expect(dbMocks.revokeApiKey).toHaveBeenCalledWith(expect.anything(), "demo", "key-1");
    await app.close();
  });
});
