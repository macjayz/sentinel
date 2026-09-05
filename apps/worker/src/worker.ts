import { Redis } from "ioredis";
import { assessThreat, SentinelEventSchema, withSpan } from "@sentinel/shared";
import { deliverPendingAlerts } from "./alerts.js";
import { loadConfig } from "./config.js";
import { countRecentIpRequests, createIncidentIfNeeded, createPool, persistEvent } from "./db.js";

export async function runWorker() {
  const config = loadConfig();
  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
  const pool = createPool(config);

  try {
    await redis.xgroup("CREATE", config.streamName, config.groupName, "$", "MKSTREAM");
  } catch (error) {
    if (!(error instanceof Error) || !error.message.includes("BUSYGROUP")) throw error;
  }

  async function tick() {
    const response = await redis.xreadgroup(
      "GROUP",
      config.groupName,
      config.consumerName,
      "COUNT",
      25,
      "BLOCK",
      5000,
      "STREAMS",
      config.streamName,
      ">"
    );

    if (!response) return;

    for (const [, messages] of response as Array<[string, Array<[string, string[]]>]>) {
      for (const [messageId, fields] of messages) {
        const eventFieldIndex = fields.findIndex((field: string) => field === "event");
        const eventJson = fields[eventFieldIndex + 1];
        const parsed = SentinelEventSchema.safeParse(JSON.parse(eventJson));

        if (parsed.success) {
          await withSpan(
            "sentinel.worker.process_event",
            {
              "sentinel.event_id": parsed.data.id,
              "sentinel.trace_id": parsed.data.traceId,
              "sentinel.project_id": parsed.data.projectId,
              "sentinel.kind": parsed.data.kind
            },
            async () => {
              const recentIpRequests = await countRecentIpRequests(
                pool,
                parsed.data.projectId,
                parsed.data.request.ip
              );
              const assessment = assessThreat(parsed.data, recentIpRequests);
              await persistEvent(pool, parsed.data, assessment);
              await createIncidentIfNeeded(pool, parsed.data, assessment);
            }
          );
        }

        await redis.xack(config.streamName, config.groupName, messageId);
      }
    }
  }

  async function deliverAlerts() {
    await deliverPendingAlerts(pool);
  }

  return {
    tick,
    deliverAlerts,
    async close() {
      await redis.quit();
      await pool.end();
    }
  };
}

if (process.env.NODE_ENV !== "test") {
  const worker = await runWorker();
  process.on("SIGTERM", () => void worker.close().then(() => process.exit(0)));
  process.on("SIGINT", () => void worker.close().then(() => process.exit(0)));

  while (true) {
    await worker.tick();
    await worker.deliverAlerts();
  }
}
