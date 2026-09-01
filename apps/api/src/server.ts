import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import Fastify from "fastify";
import { EventBatchSchema } from "@sentinel/shared";
import { loadConfig } from "./config.js";
import { createPool, getIncidents, getOverview } from "./db.js";
import { attachLiveServer } from "./live.js";
import { createRedis, enqueueEvents } from "./queue.js";

export async function buildServer() {
  const config = loadConfig();
  const app = Fastify({ logger: true });
  const pool = createPool(config);
  const redis = createRedis(config);

  await app.register(cors, { origin: true });
  await app.register(rateLimit, { max: 600, timeWindow: "1 minute" });

  app.addHook("onRequest", async (request, reply) => {
    if (request.url === "/health" || request.url.startsWith("/v1/analytics")) return;
    const apiKey = request.headers["x-sentinel-api-key"];
    if (apiKey !== config.sentinelApiKey) {
      reply.code(401).send({ error: "invalid_api_key" });
    }
  });

  app.get("/health", async () => ({ ok: true }));

  app.post("/v1/events", async (request, reply) => {
    const parsed = EventBatchSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_event_batch", details: parsed.error.flatten() });
    }

    await enqueueEvents(redis, config.streamName, parsed.data.events);
    return reply.code(202).send({ accepted: parsed.data.events.length });
  });

  app.get("/v1/analytics/overview", async () => getOverview(pool));
  app.get("/v1/analytics/incidents", async () => getIncidents(pool));

  app.addHook("onClose", async () => {
    await redis.quit();
    await pool.end();
  });

  return { app, config };
}

if (process.env.NODE_ENV !== "test") {
  const { app, config } = await buildServer();
  await app.listen({ port: config.port, host: "0.0.0.0" });
  attachLiveServer(app.server);
}
