import { randomBytes, randomUUID } from "node:crypto";
import { SentinelClient } from "@sentinel/sdk-node";
import {
  classifyResultShape,
  extractBlockHash,
  extractBlockNumber,
  extractBlockTag,
  extractRpcError,
  hashEndpoint,
  hashRpcResult,
  isThrottleSignature,
  methodCostUnits,
  normalizeRoutePath,
  resultCount,
  DEFAULT_METHOD_COST_UNITS,
  redactValue,
  type RedactionConfig,
  type SentinelEvent
} from "@sentinel/shared";
import { RpcVerifier, type VerificationEndpoint, type VerificationOptions } from "./verify.js";

export type JsonRpcParams = readonly unknown[] | Record<string, unknown>;

export type JsonRpcRequest = {
  method: string;
  params?: JsonRpcParams;
};

export type Eip1193Provider = {
  request(args: JsonRpcRequest): Promise<unknown>;
};

export type SentinelWeb3Options = {
  projectId: string;
  apiKey: string;
  endpoint: string;
  rpcUrl?: string;
  serviceName?: string;
  environment?: string;
  chainId?: string | number;
  provider?: string;
  redaction?: RedactionConfig;
  /** Provider-specific compute-unit weights, overriding the built-in defaults. */
  costUnits?: Record<string, number>;
  /**
   * Cross-provider verification (detector D2). Off unless configured: it costs real
   * requests against the endpoints you name.
   */
  verify?: VerificationOptions;
};

/**
 * The outcome of a single JSON-RPC call.
 *
 * `rpcError` is deliberately separate from a thrown error: a provider can answer HTTP 200
 * with a JSON-RPC error object in the body, and that case is invisible to any recorder
 * that only watches for exceptions. Detector D3 exists to catch exactly this.
 */
type RpcOutcome = {
  result?: unknown;
  rpcError?: { code?: number; message?: string };
  statusCode: number;
};

export function wrapEip1193Provider(provider: Eip1193Provider, options: SentinelWeb3Options): Eip1193Provider {
  const recorder = new RpcRecorder(options);

  return {
    async request(args) {
      const outcome = await recorder.record(args, async () => ({
        result: await provider.request(args),
        statusCode: 200
      }));

      return outcome.result;
    }
  };
}

export function createSentinelRpcClient(options: SentinelWeb3Options) {
  if (!options.rpcUrl) {
    throw new Error("rpcUrl is required when creating a standalone Sentinel RPC client");
  }

  const recorder = new RpcRecorder(options);

  return {
    async request(args: JsonRpcRequest) {
      const outcome = await recorder.record(args, async () => {
        const response = await fetch(options.rpcUrl!, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0",
            id: Date.now(),
            method: args.method,
            params: args.params ?? []
          })
        });

        const body = (await response.json()) as { result?: unknown; error?: unknown };

        return {
          result: body.result,
          // Recorded even when the transport succeeded. A 200 carrying an error body is
          // the failure mode this whole package exists to make visible.
          rpcError: extractRpcError(body),
          statusCode: response.status
        };
      });

      if (!isSuccessStatus(outcome.statusCode) || outcome.rpcError) {
        throw new JsonRpcError(args.method, outcome.statusCode, outcome.rpcError);
      }

      return outcome.result;
    }
  };
}

export function sentinelTransport(options: SentinelWeb3Options) {
  const client = createSentinelRpcClient(options);

  return () => ({
    config: {
      key: "sentinel",
      name: "Sentinel RPC",
      request: client.request,
      type: "http"
    },
    request: client.request
  });
}

class RpcRecorder {
  private readonly client: SentinelClient;
  private readonly endpointHash?: string;
  private readonly costTable: Record<string, number>;
  private readonly verifier?: RpcVerifier;
  private readonly headSourceUrl?: string;

  constructor(private readonly options: SentinelWeb3Options) {
    this.client = new SentinelClient({
      projectId: options.projectId,
      apiKey: options.apiKey,
      endpoint: options.endpoint,
      serviceName: options.serviceName ?? "web3-rpc",
      environment: options.environment,
      redaction: options.redaction
    });

    // Hashed once at construction. The URL itself is never stored or transmitted, because
    // provider URLs embed the API key.
    this.endpointHash = options.rpcUrl ? hashEndpoint(options.rpcUrl) : undefined;

    // Merged, not replaced: a caller correcting the weight of one method should not
    // silently drop the weights of every other method.
    this.costTable = { ...DEFAULT_METHOD_COST_UNITS, ...(options.costUnits ?? {}) };

    if (options.verify && options.verify.endpoints.length > 0) {
      // The primary joins the fan-out so that every sample produces a set of directly
      // comparable observations, all taken at the same pinned height.
      const endpoints = dedupeEndpoints([
        ...(options.rpcUrl ? [{ rpcUrl: options.rpcUrl, provider: options.provider }] : []),
        ...options.verify.endpoints
      ]);
      this.verifier = new RpcVerifier({ ...options.verify, endpoints });
      this.headSourceUrl = options.rpcUrl ?? options.verify.endpoints[0]?.rpcUrl;
    }
  }

  async record(args: JsonRpcRequest, operation: () => Promise<RpcOutcome>): Promise<RpcOutcome> {
    const started = performance.now();
    const traceId = randomBytes(16).toString("hex");

    try {
      const outcome = await operation();
      this.capture(args, traceId, Math.round(performance.now() - started), outcome);
      return outcome;
    } catch (error) {
      this.capture(args, traceId, Math.round(performance.now() - started), {
        statusCode: 500,
        rpcError: { message: error instanceof Error ? error.message : "unknown_error" }
      });
      throw error;
    }
  }

  private capture(args: JsonRpcRequest, traceId: string, latencyMs: number, outcome: RpcOutcome) {
    const addresses = extractAddresses(args.params);
    const params = args.params ?? [];
    const failed = !isSuccessStatus(outcome.statusCode) || Boolean(outcome.rpcError);

    const event: SentinelEvent = {
      id: randomUUID(),
      traceId,
      projectId: this.options.projectId,
      serviceName: this.options.serviceName ?? "web3-rpc",
      environment: this.options.environment ?? process.env.NODE_ENV ?? "development",
      timestamp: new Date().toISOString(),
      kind: "evm_rpc",
      request: {
        method: "POST",
        path: "/rpc",
        route: normalizeRoutePath("/rpc"),
        headers: {},
        query: {},
        body: redactValue(
          {
            jsonrpc: "2.0",
            method: args.method,
            params
          },
          this.options.redaction
        ),
        auth: {
          present: true,
          scheme: "RPC",
          failed
        }
      },
      response: {
        statusCode: outcome.statusCode,
        latencyMs
      },
      evmRpc: {
        method: args.method,
        chainId: this.options.chainId ? String(this.options.chainId) : undefined,
        provider: this.options.provider,
        walletAddress: addresses.walletAddress,
        contractAddress: addresses.contractAddress,
        blockTag: extractBlockTag(args.method, params),
        blockNumber: extractBlockNumber(args.method, params, outcome.result),
        blockHash: extractBlockHash(outcome.result),
        // The result is hashed, never stored: comparison without holding chain state.
        resultHash: outcome.result === undefined ? undefined : hashRpcResult(outcome.result, args.method),
        resultShape: classifyResultShape(outcome.result, Boolean(outcome.rpcError)),
        resultCount: resultCount(outcome.result),
        throttled: isThrottleSignature(
          outcome.statusCode,
          outcome.rpcError?.code,
          outcome.rpcError?.message
        ),
        rpcErrorCode: outcome.rpcError?.code,
        rpcErrorMessage: outcome.rpcError?.message,
        endpointHash: this.endpointHash,
        costUnits: methodCostUnits(args.method, this.costTable)
      }
    };

    this.client.capture(event);

    // Verification is a side observation. It is deliberately not awaited and can never
    // reject into the caller's real RPC traffic.
    if (!failed && this.verifier?.shouldVerify(args.method)) {
      void this.runVerification(args, traceId, event.evmRpc?.blockNumber).catch(() => {});
    }
  }

  private async runVerification(args: JsonRpcRequest, traceId: string, knownBlockNumber?: string) {
    if (!this.verifier) return;

    const blockNumber = await this.verifier.resolvePinHeight(knownBlockNumber, this.headSourceUrl);
    if (!blockNumber) return;

    const run = await this.verifier.verify(args.method, args.params ?? [], blockNumber);
    if (!run) return;

    for (const observation of run.observations) {
      this.client.capture({
        id: randomUUID(),
        traceId: randomBytes(16).toString("hex"),
        projectId: this.options.projectId,
        serviceName: this.options.serviceName ?? "web3-rpc",
        environment: this.options.environment ?? process.env.NODE_ENV ?? "development",
        timestamp: new Date().toISOString(),
        kind: "evm_rpc",
        request: {
          method: "POST",
          path: "/rpc",
          route: normalizeRoutePath("/rpc"),
          headers: {},
          query: {},
          body: redactValue(
            { jsonrpc: "2.0", method: args.method, params: run.pinnedParams },
            this.options.redaction
          ),
          auth: { present: true, scheme: "RPC", failed: false }
        },
        response: {
          // A JSON-RPC error still arrived as a 200; only a transport failure is a 5xx.
          statusCode:
            observation.rpcErrorMessage && observation.rpcErrorCode === undefined ? 500 : 200,
          latencyMs: observation.latencyMs
        },
        evmRpc: {
          method: args.method,
          chainId: this.options.chainId ? String(this.options.chainId) : undefined,
          provider: observation.provider,
          blockNumber: run.blockNumber,
          blockHash: observation.blockHash,
          resultHash: observation.resultHash,
          resultShape: observation.resultShape,
          resultCount: observation.resultCount,
          throttled: isThrottleSignature(
            undefined,
            observation.rpcErrorCode,
            observation.rpcErrorMessage
          ),
          rpcErrorCode: observation.rpcErrorCode,
          rpcErrorMessage: observation.rpcErrorMessage,
          endpointHash: observation.endpointHash,
          costUnits: methodCostUnits(args.method, this.costTable),
          // Ties this observation back to the call that triggered verification, and to its
          // sibling observations at the same height.
          shadowOfTraceId: traceId
        }
      });
    }
  }
}

function dedupeEndpoints(endpoints: VerificationEndpoint[]): VerificationEndpoint[] {
  const seen = new Set<string>();
  return endpoints.filter((endpoint) => {
    if (seen.has(endpoint.rpcUrl)) return false;
    seen.add(endpoint.rpcUrl);
    return true;
  });
}

class JsonRpcError extends Error {
  constructor(
    method: string,
    readonly statusCode: number,
    readonly errorBody: unknown
  ) {
    super(`JSON-RPC ${method} failed with status ${statusCode}`);
  }
}

function isSuccessStatus(statusCode: number): boolean {
  return statusCode >= 200 && statusCode < 400;
}

function extractAddresses(params: unknown) {
  const values = collectStrings(params);
  const addresses = values.filter((value) => /^0x[0-9a-f]{40}$/i.test(value));

  return {
    walletAddress: addresses[0],
    contractAddress: addresses[1]
  };
}

function collectStrings(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap((entry) => collectStrings(entry));
  if (!value || typeof value !== "object") return [];
  return Object.values(value).flatMap((entry) => collectStrings(entry));
}

export { RpcVerifier } from "./verify.js";
export type { PeerObservation, VerificationEndpoint, VerificationOptions } from "./verify.js";
