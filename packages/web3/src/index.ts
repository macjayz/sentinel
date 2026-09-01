import { randomBytes, randomUUID } from "node:crypto";
import { SentinelClient } from "@sentinel/sdk-node";
import { normalizeRoutePath, redactValue, type RedactionConfig, type SentinelEvent } from "@sentinel/shared";

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
};

export function wrapEip1193Provider(provider: Eip1193Provider, options: SentinelWeb3Options): Eip1193Provider {
  const recorder = new RpcRecorder(options);

  return {
    async request(args) {
      return recorder.record(args, () => provider.request(args));
    }
  };
}

export function createSentinelRpcClient(options: SentinelWeb3Options) {
  if (!options.rpcUrl) {
    throw new Error("rpcUrl is required when creating a standalone Sentinel RPC client");
  }

  const recorder = new RpcRecorder(options);

  return {
    request(args: JsonRpcRequest) {
      return recorder.record(args, async () => {
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
        if (!response.ok || body.error) {
          throw new JsonRpcError(args.method, response.status, body.error);
        }
        return body.result;
      });
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

  constructor(private readonly options: SentinelWeb3Options) {
    this.client = new SentinelClient({
      projectId: options.projectId,
      apiKey: options.apiKey,
      endpoint: options.endpoint,
      serviceName: options.serviceName ?? "web3-rpc",
      environment: options.environment,
      redaction: options.redaction
    });
  }

  async record(args: JsonRpcRequest, operation: () => Promise<unknown>) {
    const started = performance.now();
    const traceId = randomBytes(16).toString("hex");

    try {
      const result = await operation();
      this.capture(args, traceId, Math.round(performance.now() - started), 200);
      return result;
    } catch (error) {
      this.capture(args, traceId, Math.round(performance.now() - started), 500);
      throw error;
    }
  }

  private capture(args: JsonRpcRequest, traceId: string, latencyMs: number, statusCode: number) {
    const addresses = extractAddresses(args.params);
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
            params: args.params ?? []
          },
          this.options.redaction
        ),
        auth: {
          present: true,
          scheme: "RPC",
          failed: statusCode >= 400
        }
      },
      response: {
        statusCode,
        latencyMs
      },
      evmRpc: {
        method: args.method,
        chainId: this.options.chainId ? String(this.options.chainId) : undefined,
        provider: this.options.provider,
        walletAddress: addresses.walletAddress,
        contractAddress: addresses.contractAddress
      }
    };

    this.client.capture(event);
  }
}

class JsonRpcError extends Error {
  constructor(method: string, readonly statusCode: number, readonly errorBody: unknown) {
    super(`JSON-RPC ${method} failed with status ${statusCode}`);
  }
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
