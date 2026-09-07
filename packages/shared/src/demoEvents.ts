import { randomUUID } from "node:crypto";
import { SentinelEvent } from "./index.js";

export function buildDemoEvents(options: { projectId: string; serviceName: string }): SentinelEvent[] {
  const { projectId, serviceName } = options;
  const now = Date.now();

  return [
    ...range(60).map((index) =>
      httpEvent({
        projectId,
        serviceName,
        now,
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
        projectId,
        serviceName,
        now,
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
        projectId,
        serviceName,
        now,
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
        projectId,
        serviceName,
        now,
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
          chainId: "1",
          provider: index % 2 === 0 ? "alchemy" : "infura",
          walletAddress: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
          contractAddress: "0x0000000000000000000000000000000000000002"
        }
      })
    )
  ];
}

function httpEvent(input: {
  projectId: string;
  serviceName: string;
  now: number;
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
    traceId: randomBytesHex(16),
    projectId: input.projectId,
    serviceName: input.serviceName,
    environment: "demo",
    timestamp: new Date(input.now - input.index * 1200).toISOString(),
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

function randomBytesHex(length: number) {
  return randomUUID().replace(/-/g, "").slice(0, length * 2);
}
