export type WorkerConfig = {
  databaseUrl: string;
  redisUrl: string;
  streamName: string;
  groupName: string;
  consumerName: string;
};

export function loadConfig(): WorkerConfig {
  return {
    databaseUrl: process.env.DATABASE_URL ?? "postgres://sentinel:sentinel@localhost:5432/sentinel",
    redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
    streamName: process.env.SENTINEL_STREAM ?? "sentinel:events",
    groupName: process.env.SENTINEL_GROUP ?? "sentinel-workers",
    consumerName: process.env.SENTINEL_CONSUMER ?? `worker-${process.pid}`
  };
}
