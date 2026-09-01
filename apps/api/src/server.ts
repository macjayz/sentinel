import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { EventBatchSchema } from "@sentinel/shared";
import { loadConfig } from "./config.js";
import { createPool, getIncidents, getOverview, getRequests } from "./db.js";
import { attachLiveServer } from "./live.js";
import {
  buildMetricsSnapshot,
  buildReadiness,
  createRuntimeMetrics,
  toPrometheus
} from "./observability.js";
import { createRedis, enqueueEvents } from "./queue.js";

export async function buildServer() {
  const config = loadConfig();
  const app = Fastify({ logger: true });
  const pool = createPool(config);
  const redis = createRedis(config);
  const metrics = createRuntimeMetrics();
  const liveHub = attachLiveServer(app.server);

  await app.register(cors, { origin: true });
  await app.register(rateLimit, { max: 600, timeWindow: "1 minute" });

  app.addHook("onRequest", async (request, reply) => {
    metrics.totalRequests += 1;
    reply.header("x-request-id", request.id);

    if (
      request.url === "/health" ||
      request.url === "/ready" ||
      request.url === "/metrics" ||
      request.url.startsWith("/v1/analytics")
    ) {
      return;
    }

    const apiKey = request.headers["x-sentinel-api-key"];
    if (apiKey !== config.sentinelApiKey) {
      reply.code(401).send({ error: "invalid_api_key" });
    }
  });

  app.addHook("onResponse", async (_request, reply) => {
    const bucket = String(reply.statusCode);
    metrics.responseBuckets[bucket] = (metrics.responseBuckets[bucket] ?? 0) + 1;
  });

  app.get("/health", async () => ({ ok: true }));
  app.get("/ready", async () => buildReadiness(pool, redis, config.streamName));
  app.get("/metrics", async (_request, reply) => {
    const snapshot = await buildMetricsSnapshot(metrics, pool, redis, config.streamName, liveHub);
    reply.header("content-type", "text/plain; version=0.0.4").send(toPrometheus(snapshot));
  });

  app.post("/v1/events", async (request, reply) => {
    const parsed = EventBatchSchema.safeParse(request.body);
    if (!parsed.success) {
      metrics.failedIngestionBatches += 1;
      return reply.code(400).send({ error: "invalid_event_batch", details: parsed.error.flatten() });
    }

    await enqueueEvents(redis, config.streamName, parsed.data.events);
    metrics.ingestionBatches += 1;
    metrics.ingestionEvents += parsed.data.events.length;
    liveHub.publish("events.accepted", { count: parsed.data.events.length });
    return reply.code(202).send({ accepted: parsed.data.events.length });
  });

  app.get("/v1/analytics/overview", async () => getOverview(pool));
  app.get("/v1/analytics/incidents", async () => getIncidents(pool));
  app.get("/v1/analytics/requests", async (request) => {
    const query = request.query as {
      method?: string;
      status?: string;
      threatMin?: string;
      ip?: string;
      q?: string;
      limit?: string;
    };

    return getRequests(pool, {
      method: query.method,
      status: query.status ? Number(query.status) : undefined,
      threatMin: query.threatMin ? Number(query.threatMin) : undefined,
      ip: query.ip,
      query: query.q,
      limit: query.limit ? Number(query.limit) : undefined
    });
  });
  app.get("/v1/analytics/system", async () =>
    buildMetricsSnapshot(metrics, pool, redis, config.streamName, liveHub)
  );

  app.addHook("onClose", async () => {
    liveHub.close();
    await redis.quit();
    await pool.end();
  });

  return { app, config };
}

if (process.env.NODE_ENV !== "test") {
  const { app, config } = await buildServer();
  await app.listen({ port: config.port, host: "0.0.0.0" });
}
