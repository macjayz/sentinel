export type ApiConfig = {
  port: number;
  databaseUrl: string;
  redisUrl: string;
  sentinelApiKey: string;
  streamName: string;
  groupName: string;
};

export function loadConfig(): ApiConfig {
  return {
    port: Number(process.env.PORT ?? 8080),
    databaseUrl: process.env.DATABASE_URL ?? "postgres://sentinel:sentinel@localhost:5432/sentinel",
    redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
    sentinelApiKey: process.env.SENTINEL_API_KEY ?? "dev-sentinel-key",
    streamName: process.env.SENTINEL_STREAM ?? "sentinel:events",
    groupName: process.env.SENTINEL_GROUP ?? "sentinel-workers"
  };
}
