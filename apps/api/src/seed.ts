import pg from "pg";
import type { Redis } from "ioredis";
import { buildDemoEvents } from "@sentinel/shared";
import { enqueueEvents } from "./queue.js";

// Fixes the "docker compose up gives you an empty dashboard" problem for anyone without Node.js
// installed locally to run `npm run seed:demo` themselves. Only ever targets the "demo" project,
// and only fires once: if it already has events (from a prior boot, or real traffic), this is a
// no-op. A real signed-up user's project is never touched.
export async function seedDemoEventsIfEmpty(
  pool: pg.Pool,
  redis: Redis,
  streamName: string,
  projectId: string
): Promise<number> {
  const existing = await pool.query(`select 1 from api_events where project_id = $1 limit 1`, [projectId]);
  if (existing.rows.length > 0) return 0;

  const events = buildDemoEvents({ projectId, serviceName: "demo-api" });
  await enqueueEvents(redis, streamName, events);
  return events.length;
}
