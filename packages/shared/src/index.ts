import { context, SpanStatusCode, trace, type AttributeValue } from "@opentelemetry/api";
import { z } from "zod";

export const HttpMethodSchema = z.enum([
  "GET",
  "POST",
  "PUT",
  "PATCH",
  "DELETE",
  "OPTIONS",
  "HEAD"
]);

export const TrafficKindSchema = z.enum(["rest", "graphql", "evm_rpc", "websocket", "webhook"]);

export const SentinelEventSchema = z.object({
  id: z.string().min(8),
  traceId: z.string().regex(/^[0-9a-f]{32}$/i).optional(),
  parentSpanId: z.string().regex(/^[0-9a-f]{16}$/i).optional(),
  projectId: z.string().min(1),
  serviceName: z.string().min(1),
  environment: z.string().default("development"),
  timestamp: z.string().datetime(),
  kind: TrafficKindSchema,
  request: z.object({
    method: HttpMethodSchema,
    path: z.string(),
    route: z.string().optional(),
    ip: z.string().optional(),
    userAgent: z.string().optional(),
    headers: z.record(z.string()).default({}),
    query: z.record(z.unknown()).default({}),
    body: z.unknown().optional(),
    auth: z
      .object({
        present: z.boolean(),
        scheme: z.string().optional(),
        failed: z.boolean().default(false)
      })
      .default({ present: false, failed: false })
  }),
  response: z.object({
    statusCode: z.number().int().min(100).max(599),
    latencyMs: z.number().nonnegative(),
    bodyBytes: z.number().nonnegative().optional()
  }),
  graphQL: z
    .object({
      operationName: z.string().optional(),
      operationType: z.string().optional()
    })
    .optional(),
  evmRpc: z
    .object({
      method: z.string(),
      chainId: z.string().optional()
    })
    .optional()
});

export const EventBatchSchema = z.object({
  events: z.array(SentinelEventSchema).min(1).max(100)
});

export type SentinelEvent = z.infer<typeof SentinelEventSchema>;
export type EventBatch = z.infer<typeof EventBatchSchema>;
export type TrafficKind = z.infer<typeof TrafficKindSchema>;

export type RedactionConfig = {
  fields?: string[];
  headerFields?: string[];
  replacement?: string;
};

const defaultSensitiveFields = [
  "authorization",
  "cookie",
  "set-cookie",
  "password",
  "passcode",
  "secret",
  "token",
  "accessToken",
  "refreshToken",
  "apiKey",
  "privateKey",
  "mnemonic"
];

export function classifyTraffic(path: string, body: unknown): TrafficKind {
  if (path.toLowerCase().includes("graphql")) return "graphql";

  if (isRecord(body) && typeof body.jsonrpc === "string" && typeof body.method === "string") {
    return "evm_rpc";
  }

  return "rest";
}

export function normalizeRoutePath(path: string): string {
  const cleanPath = path.split("?")[0]?.replace(/\/+$/, "") || "/";

  return cleanPath
    .split("/")
    .map((segment) => {
      if (!segment) return segment;
      if (/^\d+$/.test(segment)) return ":id";
      if (/^[0-9a-f]{24}$/i.test(segment)) return ":objectId";
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(segment)) {
        return ":uuid";
      }
      if (/^0x[0-9a-f]{40}$/i.test(segment)) return ":address";
      if (/^0x[0-9a-f]{64}$/i.test(segment)) return ":hash";
      return segment;
    })
    .join("/");
}

export function redactValue(value: unknown, config: RedactionConfig = {}): unknown {
  const replacement = config.replacement ?? "[REDACTED]";
  const sensitive = new Set([...defaultSensitiveFields, ...(config.fields ?? [])].map(normalizeKey));

  function visit(input: unknown, key?: string): unknown {
    if (key && sensitive.has(normalizeKey(key))) return replacement;
    if (Array.isArray(input)) return input.map((entry) => visit(entry));
    if (!isRecord(input)) return input;

    return Object.fromEntries(Object.entries(input).map(([childKey, childValue]) => [childKey, visit(childValue, childKey)]));
  }

  return visit(value);
}

export function redactHeaders(headers: Record<string, string>, config: RedactionConfig = {}): Record<string, string> {
  const replacement = config.replacement ?? "[REDACTED]";
  const sensitive = new Set(
    [...defaultSensitiveFields, ...(config.headerFields ?? [])].map(normalizeKey)
  );

  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key,
      sensitive.has(normalizeKey(key)) ? replacement : value
    ])
  );
}

export type ThreatSignal = {
  name: string;
  weight: number;
  reason: string;
};

export type ThreatAssessment = {
  score: number;
  severity: "low" | "medium" | "high" | "critical";
  signals: ThreatSignal[];
};

export type TraceAttributes = Record<string, AttributeValue | undefined>;

export async function withSpan<T>(
  name: string,
  attributes: TraceAttributes,
  operation: () => Promise<T>
): Promise<T> {
  const tracer = trace.getTracer("sentinel");
  const span = tracer.startSpan(name);

  for (const [key, value] of Object.entries(attributes)) {
    if (value !== undefined) span.setAttribute(key, value);
  }

  try {
    const result = await context.with(trace.setSpan(context.active(), span), operation);
    span.setStatus({ code: SpanStatusCode.OK });
    return result;
  } catch (error) {
    span.recordException(error as Error);
    span.setStatus({
      code: SpanStatusCode.ERROR,
      message: error instanceof Error ? error.message : "unknown_error"
    });
    throw error;
  } finally {
    span.end();
  }
}

export function assessThreat(event: SentinelEvent, recentIpRequestCount = 0): ThreatAssessment {
  const signals: ThreatSignal[] = [];

  if (event.response.statusCode >= 500) {
    signals.push({ name: "server_error", weight: 18, reason: "Request produced a server error" });
  }

  if ([401, 403].includes(event.response.statusCode) || event.request.auth.failed) {
    signals.push({ name: "auth_failure", weight: 24, reason: "Authentication failed or was rejected" });
  }

  if (event.response.latencyMs > 1500) {
    signals.push({ name: "high_latency", weight: 12, reason: "Request latency exceeded 1500ms" });
  }

  if (recentIpRequestCount > 120) {
    signals.push({ name: "rate_anomaly", weight: 30, reason: "IP exceeded normal request volume" });
  }

  if (event.kind === "evm_rpc" && event.evmRpc?.method.match(/send|sign|private|unlock/i)) {
    signals.push({ name: "sensitive_rpc", weight: 26, reason: "EVM RPC method can affect keys or funds" });
  }

  if (event.kind === "graphql" && String(event.request.body ?? "").length > 10000) {
    signals.push({ name: "large_graphql_payload", weight: 14, reason: "GraphQL payload is unusually large" });
  }

  const score = Math.min(100, signals.reduce((total, signal) => total + signal.weight, 0));

  return {
    score,
    severity: score >= 75 ? "critical" : score >= 50 ? "high" : score >= 25 ? "medium" : "low",
    signals
  };
}

function normalizeKey(key: string): string {
  return key.replace(/[-_]/g, "").toLowerCase();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
