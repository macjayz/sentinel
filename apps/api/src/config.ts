export type ApiConfig = {
  port: number;
  databaseUrl: string;
  redisUrl: string;
  sentinelApiKey: string;
  allowDevFallbackApiKey: boolean;
  bootstrapDemoUser: boolean;
  seedDemoEvents: boolean;
  streamName: string;
  groupName: string;
  adminEmail: string;
  adminPassword: string;
};

export function loadConfig(): ApiConfig {
  const isProduction = process.env.NODE_ENV === "production";

  return {
    port: Number(process.env.PORT ?? 8080),
    databaseUrl: process.env.DATABASE_URL ?? "postgres://sentinel:sentinel@localhost:5432/sentinel",
    redisUrl: process.env.REDIS_URL ?? "redis://localhost:6379",
    sentinelApiKey: process.env.SENTINEL_API_KEY ?? "dev-sentinel-key",
    allowDevFallbackApiKey:
      process.env.SENTINEL_ALLOW_DEV_FALLBACK_KEY === "true" ||
      (!isProduction && process.env.SENTINEL_ALLOW_DEV_FALLBACK_KEY !== "false"),
    bootstrapDemoUser:
      process.env.SENTINEL_BOOTSTRAP_DEMO_USER === "true" ||
      (!isProduction && process.env.SENTINEL_BOOTSTRAP_DEMO_USER !== "false"),
    // Only ever seeds the "demo" project, and only when it's genuinely empty (see seedDemoEventsIfEmpty
    // in seed.ts) — never touches a real signed-up user's project, and never re-seeds on every restart.
    seedDemoEvents:
      process.env.SENTINEL_SEED_DEMO_EVENTS === "true" ||
      (!isProduction && process.env.SENTINEL_SEED_DEMO_EVENTS !== "false"),
    streamName: process.env.SENTINEL_STREAM ?? "sentinel:events",
    groupName: process.env.SENTINEL_GROUP ?? "sentinel-workers",
    adminEmail: process.env.SENTINEL_ADMIN_EMAIL ?? "owner@sentinel.local",
    adminPassword: process.env.SENTINEL_ADMIN_PASSWORD ?? "sentinel-demo"
  };
}
