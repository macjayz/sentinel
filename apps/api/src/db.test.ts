import { describe, expect, it, vi } from "vitest";
import { resolveProjectForApiKey } from "./db.js";

describe("resolveProjectForApiKey", () => {
  it("rejects the shared fallback key when dev fallback mode is disabled", async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [] }) };

    const scope = await resolveProjectForApiKey(pool as never, "dev-sentinel-key", "dev-sentinel-key", "checkout");

    expect(scope).toBeNull();
    expect(pool.query).toHaveBeenCalledOnce();
  });

  it("allows the shared fallback key only when dev fallback mode is enabled", async () => {
    const pool = { query: vi.fn() };

    const scope = await resolveProjectForApiKey(pool as never, "dev-sentinel-key", "dev-sentinel-key", "checkout", true);

    expect(scope).toEqual({ projectId: "checkout", keyId: "env-fallback" });
    expect(pool.query).not.toHaveBeenCalled();
  });

  it("ignores a requested project id for a real scoped api key", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ id: "key-1", project_id: "checkout-real" }] });
    const pool = { query };

    const scope = await resolveProjectForApiKey(pool as never, "sentinel_live_key", "dev-sentinel-key", "demo");

    expect(scope).toEqual({ projectId: "checkout-real", keyId: "key-1" });
  });
});
