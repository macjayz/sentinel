import { buildDemoEvents } from "@sentinel/shared";

const endpoint = process.env.SENTINEL_ENDPOINT ?? "http://localhost:8080";
const apiKey = process.env.SENTINEL_API_KEY ?? "dev-sentinel-key";
const projectId = process.env.SENTINEL_PROJECT_ID ?? "demo";
const serviceName = process.env.SENTINEL_SERVICE_NAME ?? "demo-api";

const events = buildDemoEvents({ projectId, serviceName });

for (const batch of chunk(events, 50)) {
  const response = await fetch(new URL("/v1/events", endpoint), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-sentinel-api-key": apiKey
    },
    body: JSON.stringify({ events: batch })
  });

  if (!response.ok) {
    throw new Error(`Failed to seed events: ${response.status} ${await response.text()}`);
  }
}

console.log(`Seeded ${events.length} demo events into ${endpoint}`);

function chunk<T>(items: T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    batches.push(items.slice(index, index + size));
  }
  return batches;
}
