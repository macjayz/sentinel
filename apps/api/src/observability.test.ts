import { describe, expect, it, vi } from "vitest";
import { buildMetricsSnapshot, createRuntimeMetrics } from "./observability.js";

const pool = {
  query: vi.fn().mockResolvedValue({ rows: [{ ok: 1 }] })
};

const liveHub = {
  connectionCount: () => 0
};

describe("api observability", () => {
  it("reports queue depth as consumer backlog, not retained stream length", async () => {
    const redis = {
      xinfo: vi
        .fn()
        .mockResolvedValue([
          "name",
          "sentinel-workers",
          "consumers",
          "1",
          "pending",
          "0",
          "last-delivered-id",
          "1-0",
          "lag",
          "0"
        ]),
      xlen: vi.fn().mockResolvedValue(138)
    };

    const snapshot = await buildMetricsSnapshot(
      createRuntimeMetrics(),
      pool as never,
      redis as never,
      "sentinel:events",
      "sentinel-workers",
      liveHub
    );

    expect(snapshot.queueDepth).toBe(0);
    expect(redis.xlen).not.toHaveBeenCalled();
  });

  it("includes pending entries in queue depth", async () => {
    const redis = {
      xinfo: vi.fn().mockResolvedValue([
        ["name", "sentinel-workers", "consumers", 1, "pending", 3, "last-delivered-id", "1-0", "lag", 7]
      ]),
      xlen: vi.fn().mockResolvedValue(20)
    };

    const snapshot = await buildMetricsSnapshot(
      createRuntimeMetrics(),
      pool as never,
      redis as never,
      "sentinel:events",
      "sentinel-workers",
      liveHub
    );

    expect(snapshot.queueDepth).toBe(10);
  });
});
