import { describe, expect, it, vi } from "vitest";
import { RpcVerifier } from "./verify.js";

const endpoints = [
  { rpcUrl: "https://a.example/key-a", provider: "alchemy" },
  { rpcUrl: "https://b.example/key-b", provider: "infura" }
];

function jsonResponse(body: unknown) {
  return { ok: true, status: 200, json: async () => body } as unknown as Response;
}

describe("eligibility", () => {
  const always = { random: () => 0, endpoints };

  it("only verifies deterministic reads", () => {
    const verifier = new RpcVerifier({ ...always, sampleRate: 1 });

    expect(verifier.shouldVerify("eth_call")).toBe(true);
    expect(verifier.shouldVerify("eth_getBalance")).toBe(true);
    // Legitimately different between endpoints — comparing these would report every
    // sample as a disagreement.
    expect(verifier.shouldVerify("eth_gasPrice")).toBe(false);
    expect(verifier.shouldVerify("eth_estimateGas")).toBe(false);
    expect(verifier.shouldVerify("eth_sendRawTransaction")).toBe(false);
  });

  it("respects the sample rate", () => {
    const rare = new RpcVerifier({ endpoints, sampleRate: 0.01, random: () => 0.5 });
    const certain = new RpcVerifier({ endpoints, sampleRate: 0.01, random: () => 0.001 });

    expect(rare.shouldVerify("eth_call")).toBe(false);
    expect(certain.shouldVerify("eth_call")).toBe(true);
  });

  it("does nothing when no endpoints are configured", () => {
    const verifier = new RpcVerifier({ endpoints: [], sampleRate: 1, random: () => 0 });

    expect(verifier.shouldVerify("eth_call")).toBe(false);
  });

  it("stops once the per-minute ceiling is reached", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ result: "0x1" }));
    // Ceiling of 4 with 2 endpoints allows exactly two fan-outs.
    const verifier = new RpcVerifier({
      endpoints,
      sampleRate: 1,
      maxCallsPerMinute: 4,
      random: () => 0,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    expect(await verifier.verify("eth_call", [{ to: "0xabc" }, "latest"], "16")).toBeDefined();
    expect(await verifier.verify("eth_call", [{ to: "0xabc" }, "latest"], "16")).toBeDefined();
    expect(await verifier.verify("eth_call", [{ to: "0xabc" }, "latest"], "16")).toBeUndefined();
    expect(verifier.shouldVerify("eth_call")).toBe(false);
    expect(fetchImpl).toHaveBeenCalledTimes(4);
  });

  it("frees budget again once the window rolls forward", async () => {
    let now = 1_000_000;
    const fetchImpl = vi.fn(async () => jsonResponse({ result: "0x1" }));
    const verifier = new RpcVerifier({
      endpoints,
      sampleRate: 1,
      maxCallsPerMinute: 2,
      random: () => 0,
      now: () => now,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    await verifier.verify("eth_call", [{ to: "0xabc" }, "latest"], "16");
    expect(verifier.shouldVerify("eth_call")).toBe(false);

    now += 61_000;
    expect(verifier.shouldVerify("eth_call")).toBe(true);
  });
});

describe("pinning", () => {
  it("asks every endpoint the same pinned question", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ result: "0x64" }));
    const verifier = new RpcVerifier({
      endpoints,
      sampleRate: 1,
      random: () => 0,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    const run = await verifier.verify("eth_call", [{ to: "0xabc" }, "latest"], "16");

    expect(run?.pinnedParams).toEqual([{ to: "0xabc" }, "0x10"]);
    for (const call of fetchImpl.mock.calls) {
      const body = JSON.parse((call[1] as RequestInit).body as string);
      // Never `latest` on the wire: that would measure head skew, not disagreement.
      expect(body.params).toEqual([{ to: "0xabc" }, "0x10"]);
    }
  });

  it("refuses to verify a call that cannot be pinned", async () => {
    const fetchImpl = vi.fn();
    const verifier = new RpcVerifier({
      endpoints,
      sampleRate: 1,
      random: () => 0,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    expect(await verifier.verify("eth_call", [{ to: "0xabc" }, "pending"], "16")).toBeUndefined();
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("prefers a height the primary response already carries", async () => {
    const fetchImpl = vi.fn();
    const verifier = new RpcVerifier({
      endpoints,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    expect(await verifier.resolvePinHeight("500", "https://a.example/key-a")).toBe("500");
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it("resolves and caches a head when the call was unpinned", async () => {
    let now = 1_000;
    const fetchImpl = vi.fn(async () => jsonResponse({ result: "0x1b4" }));
    const verifier = new RpcVerifier({
      endpoints,
      headCacheMs: 2_000,
      now: () => now,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    expect(await verifier.resolvePinHeight(undefined, "https://a.example/key-a")).toBe("436");
    expect(await verifier.resolvePinHeight(undefined, "https://a.example/key-a")).toBe("436");
    expect(fetchImpl).toHaveBeenCalledTimes(1);

    now += 3_000;
    await verifier.resolvePinHeight(undefined, "https://a.example/key-a");
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it("gives up rather than guessing when no height can be established", async () => {
    const verifier = new RpcVerifier({ endpoints });

    expect(await verifier.resolvePinHeight(undefined, undefined)).toBeUndefined();
  });
});

describe("observations", () => {
  it("hashes each endpoint's answer so they can be compared", async () => {
    const fetchImpl = vi.fn(async (url: string) =>
      jsonResponse({ result: url.includes("a.example") ? "0x64" : "0x65" })
    );
    const verifier = new RpcVerifier({
      endpoints,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    const run = await verifier.verify("eth_getBalance", ["0xabc", "latest"], "16");
    const [a, b] = run!.observations;

    expect(a.provider).toBe("alchemy");
    expect(b.provider).toBe("infura");
    expect(a.resultHash).not.toBe(b.resultHash);
    expect(a.missingBlock).toBe(false);
  });

  it("marks an endpoint that lacks the block rather than calling it a disagreement", async () => {
    const fetchImpl = vi.fn(async () =>
      jsonResponse({ error: { code: -32000, message: "header not found" } })
    );
    const verifier = new RpcVerifier({
      endpoints,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    const run = await verifier.verify("eth_getBalance", ["0xabc", "latest"], "16");

    expect(run!.observations[0].missingBlock).toBe(true);
    expect(run!.observations[0].rpcErrorCode).toBe(-32000);
    expect(run!.observations[0].resultHash).toBeUndefined();
  });

  it("treats a null result as a lagging endpoint, not a null answer", async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ result: null }));
    const verifier = new RpcVerifier({
      endpoints,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    const run = await verifier.verify("eth_getTransactionReceipt", ["0xdead"], "16");

    expect(run!.observations[0].missingBlock).toBe(true);
  });

  it("never rejects when an endpoint is unreachable", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("ECONNREFUSED");
    });
    const verifier = new RpcVerifier({
      endpoints,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    const run = await verifier.verify("eth_call", [{ to: "0xabc" }, "latest"], "16");

    expect(run!.observations).toHaveLength(2);
    expect(run!.observations[0].rpcErrorMessage).toBe("ECONNREFUSED");
    expect(run!.observations[0].missingBlock).toBe(false);
  });

  it("captures the block hash so reorg tracking has something to compare", async () => {
    const hash = `0x${"a".repeat(64)}`;
    const fetchImpl = vi.fn(async () => jsonResponse({ result: { blockHash: hash, blockNumber: "0x10" } }));
    const verifier = new RpcVerifier({
      endpoints,
      fetchImpl: fetchImpl as unknown as typeof fetch
    });

    const run = await verifier.verify("eth_getTransactionReceipt", ["0xdead"], "16");

    expect(run!.observations[0].blockHash).toBe(hash);
  });
});
