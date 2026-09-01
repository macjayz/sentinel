import pg from "pg";
import { Redis } from "ioredis";

export type RuntimeMetrics = {
  startedAt: number;
  totalRequests: number;
  ingestionEvents: number;
  ingestionBatches: number;
  failedIngestionBatches: number;
  responseBuckets: Record<string, number>;
};

export type LiveHubStats = {
  connectionCount(): number;
};

export function createRuntimeMetrics(): RuntimeMetrics {
  return {
    startedAt: Date.now(),
    totalRequests: 0,
    ingestionEvents: 0,
    ingestionBatches: 0,
    failedIngestionBatches: 0,
    responseBuckets: {}
  };
}

export async function buildReadiness(pool: pg.Pool, redis: Redis, streamName: string) {
  const [database, queue] = await Promise.all([measureDatabase(pool), measureQueue(redis, streamName)]);

  return {
    status: database.ok && queue.ok ? "ready" : "degraded",
    checks: {
      database,
      queue
    }
  };
}

export async function buildMetricsSnapshot(
  metrics: RuntimeMetrics,
  pool: pg.Pool,
  redis: Redis,
  streamName: string,
  liveHub: LiveHubStats
) {
  const [database, queueDepth] = await Promise.all([
    measureDatabase(pool),
    redis.xlen(streamName).catch(() => -1)
  ]);

  return {
    uptimeSeconds: Math.floor((Date.now() - metrics.startedAt) / 1000),
    totalRequests: metrics.totalRequests,
    ingestionRate: metrics.ingestionEvents,
    ingestionBatches: metrics.ingestionBatches,
    failedJobs: metrics.failedIngestionBatches,
    queueDepth,
    databaseLatencyMs: database.latencyMs,
    processingLatencyMs: 0,
    websocketConnections: liveHub.connectionCount(),
    responseBuckets: metrics.responseBuckets
  };
}

export function toPrometheus(snapshot: Awaited<ReturnType<typeof buildMetricsSnapshot>>): string {
  return [
    "# HELP sentinel_uptime_seconds Sentinel API process uptime.",
    "# TYPE sentinel_uptime_seconds gauge",
    `sentinel_uptime_seconds ${snapshot.uptimeSeconds}`,
    "# HELP sentinel_requests_total Total API requests handled by Sentinel.",
    "# TYPE sentinel_requests_total counter",
    `sentinel_requests_total ${snapshot.totalRequests}`,
    "# HELP sentinel_ingested_events_total Total events accepted by ingestion.",
    "# TYPE sentinel_ingested_events_total counter",
    `sentinel_ingested_events_total ${snapshot.ingestionRate}`,
    "# HELP sentinel_ingestion_batches_total Total event batches accepted by ingestion.",
    "# TYPE sentinel_ingestion_batches_total counter",
    `sentinel_ingestion_batches_total ${snapshot.ingestionBatches}`,
    "# HELP sentinel_failed_jobs_total Failed ingestion or processing jobs.",
    "# TYPE sentinel_failed_jobs_total counter",
    `sentinel_failed_jobs_total ${snapshot.failedJobs}`,
    "# HELP sentinel_queue_depth Current Redis Stream depth.",
    "# TYPE sentinel_queue_depth gauge",
    `sentinel_queue_depth ${snapshot.queueDepth}`,
    "# HELP sentinel_database_latency_ms Database health query latency.",
    "# TYPE sentinel_database_latency_ms gauge",
    `sentinel_database_latency_ms ${snapshot.databaseLatencyMs}`,
    "# HELP sentinel_processing_latency_ms Worker processing latency.",
    "# TYPE sentinel_processing_latency_ms gauge",
    `sentinel_processing_latency_ms ${snapshot.processingLatencyMs}`,
    "# HELP sentinel_websocket_connections Current dashboard WebSocket connections.",
    "# TYPE sentinel_websocket_connections gauge",
    `sentinel_websocket_connections ${snapshot.websocketConnections}`
  ].join("\n");
}

async function measureDatabase(pool: pg.Pool) {
  const started = performance.now();

  try {
    await pool.query("select 1");
    return { ok: true, latencyMs: Math.round(performance.now() - started) };
  } catch {
    return { ok: false, latencyMs: -1 };
  }
}

async function measureQueue(redis: Redis, streamName: string) {
  const started = performance.now();

  try {
    const depth = await redis.xlen(streamName);
    return { ok: true, latencyMs: Math.round(performance.now() - started), depth };
  } catch {
    return { ok: false, latencyMs: -1, depth: -1 };
  }
}
