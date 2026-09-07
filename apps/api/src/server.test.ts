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
	  revokeApiKey: vi.fn(() => true),
	  updateIncidentStatus: vi.fn(() => ({
	    id: "incident-1",
	    status: "acknowledged",
	    severity: "high",
	    title: "Test incident",
	    description: "Test",
	    created_at: new Date().toISOString()
	  })),
	  getIncidentTimeline: vi.fn(() => []),
	  listAlertDestinations: vi.fn(() => []),
	  createAlertDestination: vi.fn(() => ({
	    id: "destination-1",
	    name: "Security Operations",
	    url: "https://alerts.example.com/sentinel",
	    enabled: true,
	    created_at: new Date().toISOString()
	  })),
	  updateAlertDestination: vi.fn(() => ({
	    id: "destination-1",
	    name: "Security Operations",
	    url: "https://alerts.example.com/sentinel",
	    enabled: false,
	    created_at: new Date().toISOString()
	  })),
	  listAlertDeliveries: vi.fn(() => []),
	  listAlertRules: vi.fn(() => []),
	  createAlertRule: vi.fn(() => ({
	    id: "rule-1",
	    metric: "error_rate_percent",
	    threshold: 5,
	    window_minutes: 5,
	    enabled: true,
	    created_at: new Date().toISOString()
	  })),
	  updateAlertRule: vi.fn(() => ({
	    id: "rule-1",
	    metric: "error_rate_percent",
	    threshold: 5,
	    window_minutes: 5,
	    enabled: false,
	    created_at: new Date().toISOString()
	  })),
	  listErrorGroups: vi.fn(() => []),
	  ensureBootstrapUser: vi.fn(),
	  getUserByEmail: vi.fn((_pool: unknown, email: string) =>
	    email === "owner@sentinel.local"
	      ? {
	          id: "user-1",
	          email: "owner@sentinel.local",
	          password_hash: "test-hash",
	          organization_id: "org-1",
	          organization_name: "Demo Organization"
	        }
	      : null
	  ),
	  createSession: vi.fn(() => ({ token: "sentinel_session_owner", expiresAt: new Date().toISOString() })),
	  resolveSession: vi.fn((_pool: unknown, token?: string) => {
	    if (token === "sentinel_session_owner") {
	      return { userId: "user-1", email: "owner@sentinel.local", organizationId: "org-1", organizationName: "Demo Organization" };
	    }
	    if (token === "sentinel_session_viewer") {
	      return { userId: "user-2", email: "viewer@sentinel.local", organizationId: "org-1", organizationName: "Demo Organization" };
	    }
	    return null;
	  }),
	  deleteSession: vi.fn(),
	  listMembershipsForUser: vi.fn((_pool: unknown, userId: string) =>
	    userId === "user-1"
	      ? [{ project_id: "demo", role: "owner", name: "Demo Project" }]
	      : [{ project_id: "demo", role: "viewer", name: "Demo Project" }]
	  ),
	  getProjectRole: vi.fn((_pool: unknown, userId: string) => (userId === "user-1" ? "owner" : "viewer"))
	}));

	vi.mock("./db.js", () => ({
	  AlertRuleMetrics: ["error_rate_percent", "p95_latency_ms", "max_threat_score", "request_count", "auth_failure_count"],
	  createAlertDestination: dbMocks.createAlertDestination,
	  createAlertRule: dbMocks.createAlertRule,
	  createApiKey: dbMocks.createApiKey,
	  createPool: () => ({ end: vi.fn() }),
	  createSession: dbMocks.createSession,
	  deleteSession: dbMocks.deleteSession,
	  ensureBootstrapUser: dbMocks.ensureBootstrapUser,
	  getIncidentTimeline: dbMocks.getIncidentTimeline,
	  getOverview: dbMocks.getOverview,
	  getIncidents: () => [],
	  getProjectRole: dbMocks.getProjectRole,
	  getRequests: dbMocks.getRequests,
	  getUserByEmail: dbMocks.getUserByEmail,
	  listAlertDeliveries: dbMocks.listAlertDeliveries,
	  listAlertDestinations: dbMocks.listAlertDestinations,
	  listAlertRules: dbMocks.listAlertRules,
	  listApiKeys: dbMocks.listApiKeys,
	  listErrorGroups: dbMocks.listErrorGroups,
	  listMembershipsForUser: dbMocks.listMembershipsForUser,
	  revokeApiKey: dbMocks.revokeApiKey,
	  resolveProjectForApiKey: (_pool: unknown, apiKey: string, _fallback: string, requestedProjectId?: string) =>
	    apiKey === "dev-sentinel-key" ? { projectId: requestedProjectId ?? "demo", keyId: "test" } : null,
	  resolveSession: dbMocks.resolveSession,
	  updateAlertDestination: dbMocks.updateAlertDestination,
	  updateAlertRule: dbMocks.updateAlertRule,
	  updateIncidentStatus: dbMocks.updateIncidentStatus
	}));

vi.mock("./auth.js", async (importOriginal) => {
  const actual = await importOriginal<typeof import("./auth.js")>();
  return {
    ...actual,
    verifyPassword: vi.fn(async (password: string) => password === "correct-password")
  };
});

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

  it("passes request kind filters to analytics queries", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "GET",
      url: "/v1/analytics/requests?kind=evm_rpc&limit=10",
      headers: { "x-sentinel-api-key": "dev-sentinel-key" }
    });

    expect(response.statusCode).toBe(200);
    expect(dbMocks.getRequests).toHaveBeenCalledWith(
      expect.anything(),
      expect.objectContaining({ kind: "evm_rpc", projectId: "demo" })
    );
    await app.close();
  });

  it("scopes authenticated analytics to the requested project id", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "GET",
      url: "/v1/analytics/overview?projectId=checkout",
      headers: { "x-sentinel-api-key": "dev-sentinel-key" }
    });

    expect(response.statusCode).toBe(200);
    expect(dbMocks.getOverview).toHaveBeenCalledWith(expect.anything(), "checkout");
    await app.close();
  });

  it("defaults authenticated analytics to the demo project without a projectId", async () => {
    const { app } = await buildServer();
    const response = await app.inject({
      method: "GET",
      url: "/v1/analytics/overview",
      headers: { "x-sentinel-api-key": "dev-sentinel-key" }
    });

    expect(response.statusCode).toBe(200);
    expect(dbMocks.getOverview).toHaveBeenCalledWith(expect.anything(), "demo");
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

	  it("updates incident status within project scope", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "PATCH",
	      url: "/v1/incidents/incident-1/status",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: { status: "acknowledged" }
	    });

	    expect(response.statusCode).toBe(200);
	    expect(dbMocks.updateIncidentStatus).toHaveBeenCalledWith(
	      expect.anything(),
	      "demo",
	      "incident-1",
	      "acknowledged",
	      "demo-operator",
	      undefined
	    );
	    await app.close();
	  });

	  it("creates alert destinations within project scope", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/alert-destinations",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: { name: "Security Operations", url: "https://alerts.example.com/sentinel" }
	    });

	    expect(response.statusCode).toBe(201);
	    expect(dbMocks.createAlertDestination).toHaveBeenCalledWith(
	      expect.anything(),
	      "demo",
	      "Security Operations",
	      "https://alerts.example.com/sentinel"
	    );
	    await app.close();
	  });

	  it("updates alert destination status within project scope", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "PATCH",
	      url: "/v1/alert-destinations/destination-1",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: { enabled: false }
	    });

	    expect(response.statusCode).toBe(200);
	    expect(dbMocks.updateAlertDestination).toHaveBeenCalledWith(
	      expect.anything(),
	      "demo",
	      "destination-1",
	      false
	    );
	    await app.close();
	  });

	  it("creates alert rules within project scope", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/alert-rules",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: { metric: "error_rate_percent", threshold: 5, windowMinutes: 5 }
	    });

	    expect(response.statusCode).toBe(201);
	    expect(dbMocks.createAlertRule).toHaveBeenCalledWith(expect.anything(), "demo", "error_rate_percent", 5, 5);
	    await app.close();
	  });

	  it("rejects alert rules with an unknown metric", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/alert-rules",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: { metric: "not_a_real_metric", threshold: 5, windowMinutes: 5 }
	    });

	    expect(response.statusCode).toBe(400);
	    await app.close();
	  });

	  it("updates alert rule thresholds within project scope", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "PATCH",
	      url: "/v1/alert-rules/rule-1",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: { enabled: false }
	    });

	    expect(response.statusCode).toBe(200);
	    expect(dbMocks.updateAlertRule).toHaveBeenCalledWith(expect.anything(), "demo", "rule-1", { enabled: false });
	    await app.close();
	  });

	  it("rejects an alert rule update with no fields", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "PATCH",
	      url: "/v1/alert-rules/rule-1",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" },
	      payload: {}
	    });

	    expect(response.statusCode).toBe(400);
	    await app.close();
	  });

	  it("lists grouped errors within project scope", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "GET",
	      url: "/v1/errors",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key" }
	    });

	    expect(response.statusCode).toBe(200);
	    expect(dbMocks.listErrorGroups).toHaveBeenCalledWith(expect.anything(), "demo");
	    await app.close();
	  });

	  it("logs in with the correct password and returns a session token with real project roles", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/auth/login",
	      payload: { email: "owner@sentinel.local", password: "correct-password" }
	    });

	    expect(response.statusCode).toBe(200);
	    const body = response.json();
	    expect(body.token).toBe("sentinel_session_owner");
	    expect(body.projects).toEqual([{ id: "demo", name: "Demo Project", role: "owner" }]);
	    await app.close();
	  });

	  it("rejects login with an incorrect password", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/auth/login",
	      payload: { email: "owner@sentinel.local", password: "wrong-password" }
	    });

	    expect(response.statusCode).toBe(401);
	    await app.close();
	  });

	  it("rejects login for an unknown email", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/auth/login",
	      payload: { email: "nobody@sentinel.local", password: "correct-password" }
	    });

	    expect(response.statusCode).toBe(401);
	    await app.close();
	  });

	  it("resolves a valid session token", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "GET",
	      url: "/v1/auth/session",
	      headers: { authorization: "Bearer sentinel_session_owner" }
	    });

	    expect(response.statusCode).toBe(200);
	    expect(response.json().user.email).toBe("owner@sentinel.local");
	    await app.close();
	  });

	  it("rejects an invalid session token", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "GET",
	      url: "/v1/auth/session",
	      headers: { authorization: "Bearer not-a-real-token" }
	    });

	    expect(response.statusCode).toBe(401);
	    await app.close();
	  });

	  it("logs out by deleting the session", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/auth/logout",
	      headers: { authorization: "Bearer sentinel_session_owner" }
	    });

	    expect(response.statusCode).toBe(204);
	    expect(dbMocks.deleteSession).toHaveBeenCalledWith(expect.anything(), "sentinel_session_owner");
	    await app.close();
	  });

	  it("allows a mutating request from a session with a sufficient role", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/api-keys",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key", authorization: "Bearer sentinel_session_owner" },
	      payload: { name: "Production SDK" }
	    });

	    expect(response.statusCode).toBe(201);
	    await app.close();
	  });

	  it("rejects a mutating request from a session with an insufficient role", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/api-keys",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key", authorization: "Bearer sentinel_session_viewer" },
	      payload: { name: "Production SDK" }
	    });

	    expect(response.statusCode).toBe(403);
	    expect(dbMocks.createApiKey).not.toHaveBeenCalled();
	    await app.close();
	  });

	  it("rejects a mutating request carrying an invalid session token even with a valid api key", async () => {
	    const { app } = await buildServer();
	    const response = await app.inject({
	      method: "POST",
	      url: "/v1/api-keys",
	      headers: { "x-sentinel-api-key": "dev-sentinel-key", authorization: "Bearer not-a-real-token" },
	      payload: { name: "Production SDK" }
	    });

	    expect(response.statusCode).toBe(401);
	    await app.close();
	  });
	});
