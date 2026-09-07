import { beforeEach, describe, expect, it, vi } from "vitest";
import { seedDemoEventsIfEmpty } from "./seed.js";

const enqueueEvents = vi.hoisted(() => vi.fn());
vi.mock("./queue.js", () => ({ enqueueEvents }));

describe("seedDemoEventsIfEmpty", () => {
  beforeEach(() => {
    enqueueEvents.mockClear();
  });

  it("does nothing when the project already has events", async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [{ "?column?": 1 }] }) };
    const redis = {} as never;

    const seeded = await seedDemoEventsIfEmpty(pool as never, redis, "sentinel:events", "demo");

    expect(seeded).toBe(0);
    expect(enqueueEvents).not.toHaveBeenCalled();
  });

  it("seeds sample traffic once when the project has no events", async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [] }) };
    const redis = {} as never;

    const seeded = await seedDemoEventsIfEmpty(pool as never, redis, "sentinel:events", "demo");

    expect(seeded).toBeGreaterThan(0);
    expect(enqueueEvents).toHaveBeenCalledOnce();
    const [, , events] = enqueueEvents.mock.calls[0] as [unknown, string, Array<{ projectId: string }>];
    expect(events.length).toBe(seeded);
    expect(events.every((event) => event.projectId === "demo")).toBe(true);
  });

  it("scopes generated events to the requested project id", async () => {
    const pool = { query: vi.fn().mockResolvedValue({ rows: [] }) };
    const redis = {} as never;

    await seedDemoEventsIfEmpty(pool as never, redis, "sentinel:events", "checkout");

    const [, , events] = enqueueEvents.mock.calls[0] as [unknown, string, Array<{ projectId: string }>];
    expect(events.every((event) => event.projectId === "checkout")).toBe(true);
  });
});
