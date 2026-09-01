import type { NextFunction, Request, Response } from "express";
import { randomBytes, randomUUID } from "node:crypto";
import {
  classifyTraffic,
  EventBatch,
  normalizeRoutePath,
  RedactionConfig,
  redactHeaders,
  redactValue,
  SentinelEvent
} from "@sentinel/shared";

export type SentinelMiddlewareOptions = {
  projectId: string;
  apiKey: string;
  endpoint: string;
  serviceName: string;
  environment?: string;
  redaction?: RedactionConfig;
  flushIntervalMs?: number;
  maxBatchSize?: number;
};

export function sentinelExpress(options: SentinelMiddlewareOptions) {
  const client = new SentinelClient(options);

  return function sentinelMiddleware(req: Request, res: Response, next: NextFunction) {
    const started = performance.now();
    const chunks: Buffer[] = [];
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);

    res.write = ((chunk: Buffer | string, ...args: unknown[]) => {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      return originalWrite(chunk, ...(args as never[]));
    }) as unknown as Response["write"];

    res.end = ((chunk?: Buffer | string, ...args: unknown[]) => {
      if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      return originalEnd(chunk, ...(args as never[]));
    }) as unknown as Response["end"];

    res.on("finish", () => {
      const body = req.body;
      const kind = classifyTraffic(req.path, body);
      const headers = normalizeHeaders(req.headers);
      const authHeader = headers.authorization;
      const route = req.route?.path ? String(req.route.path) : normalizeRoutePath(req.path);
      const traceId = getTraceId(req);
      const event: SentinelEvent = {
        id: randomUUID(),
        traceId,
        projectId: options.projectId,
        serviceName: options.serviceName,
        environment: options.environment ?? process.env.NODE_ENV ?? "development",
        timestamp: new Date().toISOString(),
        kind,
        request: {
          method: req.method as SentinelEvent["request"]["method"],
          path: req.path,
          route,
          ip: req.ip,
          userAgent: headers["user-agent"],
          headers: redactHeaders(headers, options.redaction),
          query: redactValue(req.query, options.redaction) as Record<string, unknown>,
          body: redactValue(body, options.redaction),
          auth: {
            present: Boolean(authHeader),
            scheme: authHeader?.split(" ")[0],
            failed: [401, 403].includes(res.statusCode)
          }
        },
        response: {
          statusCode: res.statusCode,
          latencyMs: Math.round(performance.now() - started),
          bodyBytes: Buffer.concat(chunks).byteLength
        }
      };

      if (kind === "graphql" && isRecord(body)) {
        event.graphQL = {
          operationName: typeof body.operationName === "string" ? body.operationName : undefined,
          operationType: inferGraphQLOperation(body.query)
        };
      }

      if (kind === "evm_rpc" && isRecord(body) && typeof body.method === "string") {
        event.evmRpc = { method: body.method, chainId: headers["x-chain-id"] };
      }

      client.capture(event);
    });

    next();
  };
}

function getTraceId(req: Request) {
  const existing = req.headers["x-sentinel-trace-id"];
  if (typeof existing === "string" && /^[0-9a-f]{32}$/i.test(existing)) return existing;
  return randomBytes(16).toString("hex");
}

export class SentinelClient {
  private queue: SentinelEvent[] = [];
  private timer?: NodeJS.Timeout;

  constructor(private readonly options: SentinelMiddlewareOptions) {
    this.timer = setInterval(() => void this.flush(), options.flushIntervalMs ?? 5000);
    this.timer.unref?.();
  }

  capture(event: SentinelEvent): void {
    this.queue.push(event);
    if (this.queue.length >= (this.options.maxBatchSize ?? 25)) {
      void this.flush();
    }
  }

  async flush(): Promise<void> {
    if (this.queue.length === 0) return;
    const events = this.queue.splice(0, this.options.maxBatchSize ?? 25);
    const payload: EventBatch = { events };

    try {
      const response = await fetch(new URL("/v1/events", this.options.endpoint), {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-sentinel-api-key": this.options.apiKey
        },
        body: JSON.stringify(payload)
      });

      if (!response.ok) {
        this.queue.unshift(...events);
      }
    } catch {
      this.queue.unshift(...events);
    }
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

function normalizeHeaders(headers: Request["headers"]): Record<string, string> {
  return Object.fromEntries(
    Object.entries(headers).map(([key, value]) => [
      key.toLowerCase(),
      Array.isArray(value) ? value.join(",") : String(value ?? "")
    ])
  );
}

function inferGraphQLOperation(query: unknown): string | undefined {
  if (typeof query !== "string") return undefined;
  const match = query.trim().match(/^(query|mutation|subscription)\b/);
  return match?.[1];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}
