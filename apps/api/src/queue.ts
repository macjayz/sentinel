import { Redis } from "ioredis";
import { SentinelEvent, withSpan } from "@sentinel/shared";
import { ApiConfig } from "./config.js";

export function createRedis(config: ApiConfig) {
  return new Redis(config.redisUrl, { maxRetriesPerRequest: null });
}

export async function enqueueEvents(redis: Redis, streamName: string, events: SentinelEvent[]) {
  return withSpan(
    "sentinel.redis.enqueue_events",
    {
      "sentinel.stream": streamName,
      "sentinel.events.count": events.length
    },
    async () => {
      const pipeline = redis.pipeline();

      for (const event of events) {
        pipeline.xadd(streamName, "*", "event", JSON.stringify(event));
      }

      await pipeline.exec();
    }
  );
}
