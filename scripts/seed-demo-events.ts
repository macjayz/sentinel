import { randomUUID } from "node:crypto";
import { SentinelEvent } from "@sentinel/shared";

const endpoint = process.env.SENTINEL_ENDPOINT ?? "http://localhost:8080";
const apiKey = process.env.SENTINEL_API_KEY ?? "dev-sentinel-key";
const projectId = process.env.SENTINEL_PROJECT_ID ?? "demo";
const serviceName = process.env.SENTINEL_SERVICE_NAME ?? "demo-api";

const now = Date.now();
const events: SentinelEvent[] = [
  ...range(60).map((index) =>
    httpEvent({
      index,
      method: "GET",
      path: `/api/users/${1000 + index}`,
      route: "/api/users/:id",
      statusCode: 200,
      latencyMs: 35 + (index % 40),
      ip: `198.51.100.${10 + (index % 8)}`
    })
  ),
  ...range(35).map((index) =>
    httpEvent({
      index: index + 60,
      method: "POST",
      path: "/api/login",
      route: "/api/login",
      statusCode: index % 3 === 0 ? 401 : 403,
      latencyMs: 70 + (index % 20),
      ip: "203.0.113.14",
      authFailed: true
    })
  ),
  ...range(25).map((index) =>
    httpEvent({
      index: index + 95,
      method: "POST",
      path: "/graphql",
      route: "/graphql",
      statusCode: index % 10 === 0 ? 500 : 200,
      latencyMs: 110 + (index % 90),
      ip: `192.0.2.${20 + (index % 6)}`,
      kind: "graphql",
      graphQL: { operationName: index % 2 === 0 ? "GetAccount" : "UpdateProfile", operationType: "query" }
    })
  ),
  ...range(18).map((index) =>
    httpEvent({
      index: index + 120,
      method: "POST",
      path: "/rpc",
      route: "/rpc",
      statusCode: index % 4 === 0 ? 401 : 200,
      latencyMs: 55 + (index % 50),
      ip: "198.51.100.22",
      authFailed: index % 4 === 0,
      kind: "evm_rpc",
      evmRpc: {
        method: index % 4 === 0 ? "eth_sendRawTransaction" : "eth_call",
        chainId: "1"
      }
    })
  )
];

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

function httpEvent(input: {
  index: number;
  method: SentinelEvent["request"]["method"];
  path: string;
  route: string;
  statusCode: number;
  latencyMs: number;
  ip: string;
  authFailed?: boolean;
  kind?: SentinelEvent["kind"];
  graphQL?: SentinelEvent["graphQL"];
  evmRpc?: SentinelEvent["evmRpc"];
}): SentinelEvent {
  return {
    id: randomUUID(),
    projectId,
    serviceName,
    environment: "demo",
    timestamp: new Date(now - input.index * 1200).toISOString(),
    kind: input.kind ?? "rest",
    request: {
      method: input.method,
      path: input.path,
      route: input.route,
      ip: input.ip,
      userAgent: input.index % 5 === 0 ? "curl/8.0" : "Mozilla/5.0",
      headers: {
        "content-type": "application/json",
        authorization: "[REDACTED]"
      },
      query: {},
      body: requestBody(input),
      auth: {
        present: true,
        scheme: "Bearer",
        failed: input.authFailed ?? false
      }
    },
    response: {
      statusCode: input.statusCode,
      latencyMs: input.latencyMs,
      bodyBytes: 512 + input.index
    },
    graphQL: input.graphQL,
    evmRpc: input.evmRpc
  };
}

function requestBody(input: { kind?: SentinelEvent["kind"]; graphQL?: SentinelEvent["graphQL"]; evmRpc?: SentinelEvent["evmRpc"] }) {
  if (input.kind === "graphql") {
    return {
      operationName: input.graphQL?.operationName,
      query: "query GetAccount { account { id email } }"
    };
  }

  if (input.kind === "evm_rpc") {
    return {
      jsonrpc: "2.0",
      id: 1,
      method: input.evmRpc?.method,
      params: []
    };
  }

  return { sample: true };
}

function range(count: number) {
  return Array.from({ length: count }, (_, index) => index);
}

function chunk<T>(items: T[], size: number): T[][] {
  const batches: T[][] = [];
  for (let index = 0; index < items.length; index += size) {
    batches.push(items.slice(index, index + size));
  }
  return batches;
}
