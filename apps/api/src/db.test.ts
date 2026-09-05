import { describe, expect, it, vi } from "vitest";
import { resolveProjectForApiKey } from "./db.js";

describe("resolveProjectForApiKey", () => {
  it("scopes the shared fallback key to the requested project", async () => {
    const pool = { query: vi.fn() };

    const scope = await resolveProjectForApiKey(pool as never, "dev-sentinel-key", "dev-sentinel-key", "checkout");

    expect(scope).toEqual({ projectId: "checkout", keyId: "env-fallback" });
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("defaults the shared fallback key to the demo project without a request", async () => {
    const pool = { query: vi.fn() };

    const scope = await resolveProjectForApiKey(pool as never, "dev-sentinel-key", "dev-sentinel-key");

    expect(scope).toEqual({ projectId: "demo", keyId: "env-fallback" });
  });

  it("ignores a requested project id for a real scoped api key", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ id: "key-1", project_id: "checkout-real" }] });
    const pool = { query };

    const scope = await resolveProjectForApiKey(pool as never, "sentinel_live_key", "dev-sentinel-key", "demo");

    expect(scope).toEqual({ projectId: "checkout-real", keyId: "key-1" });
  });
});
