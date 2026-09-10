import { describe, expect, it } from "vitest";
import {
  chainBlockTimeMs,
  classifyResultShape,
  extractBlockHash,
  extractBlockNumber,
  extractBlockTag,
  extractRpcError,
  hashEndpoint,
  hashRpcResult,
  methodCostUnits,
  normalizeRpcResult,
  pinBlockTag,
  isThrottleSignature,
  isVerifiableMethod
} from "./rpc.js";

describe("normalizeRpcResult", () => {
  it("ignores key order", () => {
    const a = { blockNumber: "0x1", hash: "0xabc", from: "0xdef" };
    const b = { from: "0xdef", hash: "0xabc", blockNumber: "0x1" };

    expect(hashRpcResult(a)).toBe(hashRpcResult(b));
  });

  it("ignores hex case", () => {
    expect(hashRpcResult("0xABCDEF")).toBe(hashRpcResult("0xabcdef"));
  });

  it("drops undefined keys but keeps explicit null", () => {
    expect(normalizeRpcResult({ a: 1, b: undefined })).toEqual({ a: 1 });
    expect(normalizeRpcResult({ a: 1, b: null })).toEqual({ a: 1, b: null });
    expect(hashRpcResult({ a: 1, b: undefined })).not.toBe(hashRpcResult({ a: 1, b: null }));
  });

  it("strips leading zeros from QUANTITY results", () => {
    expect(normalizeRpcResult("0x01b4", "eth_blockNumber")).toBe("0x1b4");
    expect(hashRpcResult("0x01b4", "eth_blockNumber")).toBe(hashRpcResult("0x1b4", "eth_blockNumber"));
  });

  it("normalizes a zero QUANTITY to 0x0 rather than 0x", () => {
    expect(normalizeRpcResult("0x0000", "eth_getBalance")).toBe("0x0");
    expect(normalizeRpcResult("0x", "eth_getBalance")).toBe("0x0");
  });

  it("never strips leading zeros from DATA results", () => {
    // eth_call returns DATA. A uint256(1) return value is 32 padded bytes and must not
    // collapse into a bare 0x1 — that would hash two different answers identically.
    const padded = `0x${"0".repeat(63)}1`;

    expect(normalizeRpcResult(padded, "eth_call")).toBe(padded);
    expect(hashRpcResult(padded, "eth_call")).not.toBe(hashRpcResult("0x1", "eth_call"));
  });

  it("strips leading zeros from QUANTITY fields nested in objects", () => {
    const a = { blockNumber: "0x01b4", gasUsed: "0x05" };
    const b = { blockNumber: "0x1b4", gasUsed: "0x5" };

    expect(hashRpcResult(a)).toBe(hashRpcResult(b));
  });

  it("leaves DATA fields nested in objects byte-aligned", () => {
    const a = { blockHash: `0x${"0".repeat(63)}1` };
    const b = { blockHash: "0x1" };

    expect(hashRpcResult(a)).not.toBe(hashRpcResult(b));
  });

  it("sorts logs into chain order for eth_getLogs", () => {
    const ordered = [
      { blockNumber: "0x1", logIndex: "0x0", data: "0xaa" },
      { blockNumber: "0x1", logIndex: "0x1", data: "0xbb" },
      { blockNumber: "0x2", logIndex: "0x0", data: "0xcc" }
    ];
    const shuffled = [ordered[2], ordered[0], ordered[1]];

    expect(hashRpcResult(shuffled, "eth_getLogs")).toBe(hashRpcResult(ordered, "eth_getLogs"));
  });

  it("does not reorder arrays for methods with meaningful order", () => {
    const a = ["0x1", "0x2"];
    const b = ["0x2", "0x1"];

    expect(hashRpcResult(a, "eth_getBlockByNumber")).not.toBe(hashRpcResult(b, "eth_getBlockByNumber"));
  });

  it("still detects genuine disagreement", () => {
    // The whole point: formatting is normalized away, values are not.
    expect(hashRpcResult("0x64", "eth_getBalance")).not.toBe(hashRpcResult("0x65", "eth_getBalance"));
  });

  it("distinguishes null from an empty array", () => {
    expect(hashRpcResult(null)).not.toBe(hashRpcResult([]));
  });
});

describe("classifyResultShape", () => {
  it("classifies the shapes silent-failure detection depends on", () => {
    expect(classifyResultShape(null)).toBe("null");
    expect(classifyResultShape(undefined)).toBe("null");
    expect(classifyResultShape([])).toBe("empty_array");
    expect(classifyResultShape(["0x1"])).toBe("value");
    expect(classifyResultShape("0x1")).toBe("value");
    expect(classifyResultShape(null, true)).toBe("error_in_body");
  });
});

describe("hashEndpoint", () => {
  it("never returns the url it was given", () => {
    const url = "https://eth-mainnet.g.alchemy.com/v2/secret-api-key";
    const hashed = hashEndpoint(url);

    expect(hashed).not.toContain("secret-api-key");
    expect(hashed).not.toContain("alchemy");
    expect(hashed).toMatch(/^[0-9a-f]{32}$/);
  });

  it("distinguishes two endpoints of the same provider", () => {
    expect(hashEndpoint("https://rpc.example/v2/key-a")).not.toBe(hashEndpoint("https://rpc.example/v2/key-b"));
  });

  it("is stable for the same url", () => {
    expect(hashEndpoint("https://rpc.example/v2/key")).toBe(hashEndpoint("https://rpc.example/v2/key"));
  });
});

describe("block metadata extraction", () => {
  it("reads the caller's block tag from the right param position", () => {
    expect(extractBlockTag("eth_call", [{ to: "0x1" }, "latest"])).toBe("latest");
    expect(extractBlockTag("eth_getBalance", ["0xabc", "0x10"])).toBe("0x10");
    expect(extractBlockTag("eth_getStorageAt", ["0xabc", "0x0", "finalized"])).toBe("finalized");
    expect(extractBlockTag("eth_sendRawTransaction", ["0xdeadbeef"])).toBeUndefined();
  });

  it("prefers the height the provider actually answered from", () => {
    expect(extractBlockNumber("eth_getTransactionReceipt", ["0xabc"], { blockNumber: "0x10" })).toBe("16");
  });

  it("falls back to a numeric block tag in the request", () => {
    expect(extractBlockNumber("eth_getBalance", ["0xabc", "0x10"], "0x64")).toBe("16");
  });

  it("resolves eth_blockNumber from its own result", () => {
    expect(extractBlockNumber("eth_blockNumber", [], "0x1b4")).toBe("436");
  });

  it("returns no height for an unpinned latest call", () => {
    expect(extractBlockNumber("eth_getBalance", ["0xabc", "latest"], "0x64")).toBeUndefined();
  });

  it("extracts a block hash from a receipt and from a block", () => {
    const hash = `0x${"a".repeat(64)}`;

    expect(extractBlockHash({ blockHash: hash })).toBe(hash);
    expect(extractBlockHash({ hash, parentHash: `0x${"b".repeat(64)}` })).toBe(hash);
    expect(extractBlockHash({ hash })).toBeUndefined();
    expect(extractBlockHash(null)).toBeUndefined();
  });
});

describe("extractRpcError", () => {
  it("finds a JSON-RPC error carried inside a success body", () => {
    expect(extractRpcError({ jsonrpc: "2.0", error: { code: -32000, message: "header not found" } })).toEqual({
      code: -32000,
      message: "header not found"
    });
  });

  it("returns nothing for a clean body", () => {
    expect(extractRpcError({ jsonrpc: "2.0", result: "0x1" })).toBeUndefined();
    expect(extractRpcError(null)).toBeUndefined();
  });
});

describe("cost and chain tables", () => {
  it("weights known methods and leaves unknown ones unpriced", () => {
    expect(methodCostUnits("eth_getLogs")).toBe(75);
    expect(methodCostUnits("eth_chainId")).toBe(0);
    expect(methodCostUnits("debug_traceTransaction")).toBeUndefined();
  });

  it("knows block times for supported chains only", () => {
    expect(chainBlockTimeMs("1")).toBe(12_000);
    expect(chainBlockTimeMs("8453")).toBe(2_000);
    expect(chainBlockTimeMs("999999")).toBeUndefined();
    expect(chainBlockTimeMs(undefined)).toBeUndefined();
  });
});

describe("pinBlockTag", () => {
  it("rewrites a latest tag to a concrete height", () => {
    expect(pinBlockTag("eth_call", [{ to: "0xabc" }, "latest"], "16")).toEqual([{ to: "0xabc" }, "0x10"]);
    expect(pinBlockTag("eth_getBalance", ["0xabc", "latest"], "255")).toEqual(["0xabc", "0xff"]);
  });

  it("rewrites a tag the caller already pinned, so both sides match exactly", () => {
    expect(pinBlockTag("eth_getStorageAt", ["0xabc", "0x0", "0x5"], "5")).toEqual(["0xabc", "0x0", "0x5"]);
  });

  it("refuses to pin a pending call", () => {
    // A pending result is not fixed, so two endpoints can differ legitimately.
    expect(pinBlockTag("eth_call", [{ to: "0xabc" }, "pending"], "16")).toBeUndefined();
  });

  it("passes through methods that carry no block tag", () => {
    // A receipt is pinned by its transaction hash already.
    expect(pinBlockTag("eth_getTransactionReceipt", ["0xdead"], "16")).toEqual(["0xdead"]);
  });

  it("pins a log filter's range rather than a positional tag", () => {
    expect(pinBlockTag("eth_getLogs", [{ address: "0xabc", fromBlock: "latest", toBlock: "latest" }], "16")).toEqual([
      { address: "0xabc", fromBlock: "0x10", toBlock: "0x10" }
    ]);
  });

  it("leaves an already-numeric log range untouched", () => {
    expect(pinBlockTag("eth_getLogs", [{ fromBlock: "0x1", toBlock: "0x2" }], "16")).toEqual([
      { fromBlock: "0x1", toBlock: "0x2" }
    ]);
  });

  it("keeps a hash-scoped log filter as-is", () => {
    const filter = { blockHash: `0x${"a".repeat(64)}` };
    expect(pinBlockTag("eth_getLogs", [filter], "16")).toEqual([filter]);
  });

  it("refuses to pin a pending log range", () => {
    expect(pinBlockTag("eth_getLogs", [{ fromBlock: "pending" }], "16")).toBeUndefined();
  });

  it("refuses nonsense heights and non-array params", () => {
    expect(pinBlockTag("eth_call", [{}, "latest"], "not-a-number")).toBeUndefined();
    expect(pinBlockTag("eth_call", { to: "0xabc" }, "16")).toBeUndefined();
  });
});

describe("isVerifiableMethod", () => {
  it("allows deterministic reads", () => {
    expect(isVerifiableMethod("eth_call")).toBe(true);
    expect(isVerifiableMethod("eth_getBalance")).toBe(true);
  });

  it("refuses methods whose answers legitimately differ between endpoints", () => {
    expect(isVerifiableMethod("eth_gasPrice")).toBe(false);
    expect(isVerifiableMethod("eth_estimateGas")).toBe(false);
    expect(isVerifiableMethod("eth_sendRawTransaction")).toBe(false);
  });
});

describe("isThrottleSignature", () => {
  it("recognises a clean 429", () => {
    expect(isThrottleSignature(429, undefined, undefined)).toBe(true);
  });

  it("recognises throttling delivered as a JSON-RPC error inside a 200", () => {
    expect(isThrottleSignature(200, -32005, "limit exceeded")).toBe(true);
    expect(isThrottleSignature(200, undefined, "Your app has exceeded its compute unit per second capacity")).toBe(true);
    expect(isThrottleSignature(200, undefined, "rate-limit reached")).toBe(true);
    expect(isThrottleSignature(200, undefined, "Too Many Requests")).toBe(true);
  });

  it("does not mistake ordinary execution errors for throttling", () => {
    // The reason the message pattern is narrow: these must not read as rate limiting.
    expect(isThrottleSignature(200, -32000, "gas limit exceeded")).toBe(false);
    expect(isThrottleSignature(200, -32000, "execution reverted")).toBe(false);
    expect(isThrottleSignature(200, -32000, "header not found")).toBe(false);
    expect(isThrottleSignature(200, undefined, undefined)).toBe(false);
  });
});
