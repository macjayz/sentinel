import { describe, expect, it, vi } from "vitest";
import { wrapEip1193Provider } from "./index.js";

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
