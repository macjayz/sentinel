import { describe, expect, it, vi } from "vitest";
import { createSentinelRpcClient, wrapEip1193Provider } from "./index.js";

const captured: unknown[] = [];

vi.mock("@sentinel/sdk-node", () => ({
  SentinelClient: class {
    capture(event: unknown) {
      captured.push(event);
    }
  }
}));

describe("web3 sdk", () => {
  it("records successful json-rpc calls", async () => {
    captured.length = 0;
    const provider = wrapEip1193Provider(
      {
        request: vi.fn(async () => "0x1")
      },
      {
        projectId: "demo",
        apiKey: "dev-sentinel-key",
        endpoint: "http://localhost:8080",
        chainId: 1,
        provider: "alchemy"
      }
    );

    await provider.request({ method: "eth_call", params: [{ to: "0x0000000000000000000000000000000000000001" }] });

    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      kind: "evm_rpc",
      evmRpc: {
        method: "eth_call",
        chainId: "1",
        provider: "alchemy",
        walletAddress: "0x0000000000000000000000000000000000000001"
      },
      response: {
        statusCode: 200
      }
    });
  });

  it("marks failed json-rpc calls as failed auth-style rpc events", async () => {
    captured.length = 0;
    const provider = wrapEip1193Provider(
      {
        request: vi.fn(async () => {
          throw new Error("provider failed");
        })
      },
      {
        projectId: "demo",
        apiKey: "dev-sentinel-key",
        endpoint: "http://localhost:8080"
      }
    );

    await expect(provider.request({ method: "eth_sendRawTransaction", params: [] })).rejects.toThrow("provider failed");
    expect(captured[0]).toMatchObject({
      evmRpc: { method: "eth_sendRawTransaction" },
      request: { auth: { failed: true } },
      response: { statusCode: 500 }
    });
  });
});

describe("result capture", () => {
  const baseOptions = {
    projectId: "demo",
    apiKey: "dev-sentinel-key",
    endpoint: "http://localhost:8080",
    chainId: 1,
    provider: "alchemy"
  };

  it("records the block the call resolved against and a hash of the result", async () => {
    captured.length = 0;
    const provider = wrapEip1193Provider(
      { request: vi.fn(async () => "0x64") },
      baseOptions
    );

    await provider.request({ method: "eth_getBalance", params: ["0xabc", "0x10"] });

    expect(captured[0]).toMatchObject({
      evmRpc: {
        method: "eth_getBalance",
        blockTag: "0x10",
        blockNumber: "16",
        resultShape: "value",
        costUnits: 19
      }
    });
    expect((captured[0] as any).evmRpc.resultHash).toMatch(/^[0-9a-f]{32}$/);
  });

  it("hashes equal results identically across differently-formatted responses", async () => {
    captured.length = 0;
    const first = wrapEip1193Provider({ request: vi.fn(async () => "0x01b4") }, baseOptions);
    const second = wrapEip1193Provider({ request: vi.fn(async () => "0x1B4") }, baseOptions);

    await first.request({ method: "eth_blockNumber", params: [] });
    await second.request({ method: "eth_blockNumber", params: [] });

    const [a, b] = captured as any[];
    expect(a.evmRpc.resultHash).toBe(b.evmRpc.resultHash);
  });

  it("records a null result as a shape rather than as a failure", async () => {
    captured.length = 0;
    const provider = wrapEip1193Provider({ request: vi.fn(async () => null) }, baseOptions);

    await provider.request({ method: "eth_getTransactionReceipt", params: ["0xdead"] });

    expect(captured[0]).toMatchObject({
      evmRpc: { resultShape: "null" },
      response: { statusCode: 200 },
      request: { auth: { failed: false } }
    });
  });

  it("records a JSON-RPC error carried inside an HTTP 200 body", async () => {
    captured.length = 0;
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", error: { code: -32000, message: "header not found" } })
    }));
    vi.stubGlobal("fetch", fetchMock);

    const client = createSentinelRpcClient({ ...baseOptions, rpcUrl: "https://rpc.example/v2/secret" });

    await expect(client.request({ method: "eth_call", params: [{ to: "0xabc" }, "latest"] })).rejects.toThrow();

    // The transport succeeded — this is the failure that every status-code-based monitor misses.
    expect(captured[0]).toMatchObject({
      response: { statusCode: 200 },
      evmRpc: {
        resultShape: "error_in_body",
        rpcErrorCode: -32000,
        rpcErrorMessage: "header not found"
      }
    });

    vi.unstubAllGlobals();
  });

  it("never lets the rpc url reach the captured event", async () => {
    captured.length = 0;
    const fetchMock = vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({ jsonrpc: "2.0", result: "0x1" })
    }));
    vi.stubGlobal("fetch", fetchMock);

    const client = createSentinelRpcClient({
      ...baseOptions,
      rpcUrl: "https://eth-mainnet.g.alchemy.com/v2/super-secret-key"
    });

    await client.request({ method: "eth_blockNumber", params: [] });

    const serialized = JSON.stringify(captured[0]);
    expect(serialized).not.toContain("super-secret-key");
    expect(serialized).not.toContain("alchemy.com");
    expect((captured[0] as any).evmRpc.endpointHash).toMatch(/^[0-9a-f]{32}$/);

    vi.unstubAllGlobals();
  });

  it("merges custom cost weights over the defaults instead of replacing them", async () => {
    captured.length = 0;
    const provider = wrapEip1193Provider(
      { request: vi.fn(async () => "0x1") },
      { ...baseOptions, costUnits: { eth_call: 5 } }
    );

    await provider.request({ method: "eth_call", params: [{ to: "0xabc" }, "latest"] });
    await provider.request({ method: "eth_getLogs", params: [{}] });

    const [overridden, defaulted] = captured as any[];
    expect(overridden.evmRpc.costUnits).toBe(5);
    expect(defaulted.evmRpc.costUnits).toBe(75);
  });
});
