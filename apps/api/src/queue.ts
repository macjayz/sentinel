import { Redis } from "ioredis";
import { SentinelEvent } from "@sentinel/shared";
import { ApiConfig } from "./config.js";

export function createRedis(config: ApiConfig) {
  return new Redis(config.redisUrl, { maxRetriesPerRequest: null });
}

export async function enqueueEvents(redis: Redis, streamName: string, events: SentinelEvent[]) {
  const pipeline = redis.pipeline();

  for (const event of events) {
    pipeline.xadd(streamName, "*", "event", JSON.stringify(event));
  }

  await pipeline.exec();
}
