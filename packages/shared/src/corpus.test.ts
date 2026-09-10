import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { hashRpcResult, normalizeRpcResult } from "./rpc.js";

/**
 * Differential normalization tests against real provider output.
 *
 * Cross-provider verification (detector D2) is only as trustworthy as normalization. If
 * normalization is too weak, honest providers look like they disagree over formatting and
 * every sample is a false positive. If it is too strong, genuinely different answers
 * collapse into one hash and real disagreement goes unreported.
 *
 * Hand-written fixtures cannot settle that, because the formatting differences that matter
 * are the ones nobody thinks to invent. These fixtures are recorded verbatim from five
 * public Ethereum endpoints — regenerate with:
 *
 *   npx tsx scripts/record-normalization-corpus.ts
 */

type CorpusFile = {
  method: string;
  params: unknown[];
  responses: Record<string, { result?: unknown; error?: unknown; __recorderError?: string }>;
};

const corpusDir = fileURLToPath(new URL("../corpus", import.meta.url));

const manifest = JSON.parse(readFileSync(`${corpusDir}/manifest.json`, "utf8")) as {
  blockNumber: string;
  endpoints: string[];
};

const files = readdirSync(corpusDir)
  .filter((name) => name.endsWith(".json") && name !== "manifest.json")
  .sort();

function load(file: string): CorpusFile {
  return JSON.parse(readFileSync(`${corpusDir}/${file}`, "utf8")) as CorpusFile;
}

/** Only responses that actually carried a result can be compared. */
function answered(corpus: CorpusFile) {
  return Object.entries(corpus.responses).filter(
    ([, body]) => body && !body.__recorderError && "result" in body
  );
}

describe("normalization corpus", () => {
  it("was recorded from several endpoints at one pinned height", () => {
    expect(files.length).toBeGreaterThanOrEqual(8);
    expect(manifest.endpoints.length).toBeGreaterThanOrEqual(3);
    expect(Number(manifest.blockNumber)).toBeGreaterThan(0);
  });

  it("contains genuine formatting variance, so these tests are not vacuous", () => {
    // If every provider returned byte-identical bodies, agreement after normalization
    // would prove nothing at all. At least one call must differ before normalization.
    const callsWithRawVariance = files.filter((file) => {
      const corpus = load(file);
      const raw = new Set(answered(corpus).map(([, body]) => JSON.stringify(body.result)));
      return raw.size > 1;
    });

    expect(callsWithRawVariance.length).toBeGreaterThan(0);
  });

  it("varies in envelope key order across providers", () => {
    const orders = new Set<string>();
    for (const file of files) {
      for (const [, body] of Object.entries(load(file).responses)) {
        if (body && !body.__recorderError) orders.add(Object.keys(body).join(","));
      }
    }

    // Providers disagree on `{jsonrpc, result, id}` vs `{id, jsonrpc, result}`. That is
    // exactly the kind of difference normalization must not care about.
    expect(orders.size).toBeGreaterThan(1);
  });
});

describe.each(files)("%s", (file) => {
  const corpus = load(file);
  const responses = answered(corpus);

  it("was answered by at least three endpoints", () => {
    expect(responses.length).toBeGreaterThanOrEqual(3);
  });

  it("normalizes to a single hash across every endpoint", () => {
    const byHash = new Map<string, string[]>();

    for (const [name, body] of responses) {
      const hash = hashRpcResult(body.result, corpus.method);
      byHash.set(hash, [...(byHash.get(hash) ?? []), name]);
    }

    // A readable failure matters here: when this breaks, the useful information is which
    // providers landed on which hash, not simply that a count was wrong.
    const grouping = [...byHash.entries()]
      .map(([hash, names]) => `${hash.slice(0, 8)}: ${names.join(", ")}`)
      .join(" | ");

    expect(byHash.size, `expected one hash, got ${byHash.size} — ${grouping}`).toBe(1);
  });

  it("is stable when normalized twice", () => {
    for (const [, body] of responses) {
      const once = normalizeRpcResult(body.result, corpus.method);
      const twice = normalizeRpcResult(once, corpus.method);
      expect(twice).toEqual(once);
    }
  });

  it("still distinguishes a genuinely altered value", () => {
    // The guard against over-normalization: perturb one leaf and the hash must move.
    const [, body] = responses[0];
    const original = hashRpcResult(body.result, corpus.method);
    const altered = hashRpcResult(perturb(body.result), corpus.method);

    expect(altered).not.toBe(original);
  });
});

/** Change exactly one primitive leaf, leaving the shape identical. */
function perturb(value: unknown): unknown {
  if (typeof value === "string") {
    return value.startsWith("0x") ? `0x${flipFirstDigit(value.slice(2))}` : `${value}!`;
  }
  if (Array.isArray(value)) {
    return value.length === 0 ? ["0xdeadbeef"] : [perturb(value[0]), ...value.slice(1)];
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) return { perturbed: true };
    const [key, first] = entries[0];
    return { ...(value as Record<string, unknown>), [key]: perturb(first) };
  }
  if (typeof value === "number") return value + 1;
  if (typeof value === "boolean") return !value;
  return "perturbed";
}

function flipFirstDigit(hex: string): string {
  if (hex.length === 0) return "1";
  const first = hex[0] === "f" ? "e" : "f";
  return `${first}${hex.slice(1)}`;
}

/**
 * Derived variants.
 *
 * The five endpoints above happened to agree closely: identical key sets and values,
 * differing only in key order. That is a real and useful result, but it leaves formatting
 * differences that are documented to occur between providers untested — leading zeros on
 * quantities, hex case, and log ordering.
 *
 * These cases are therefore *synthetic mutations of the real recorded responses*, not
 * observed provider behaviour. They are labelled as such deliberately: the corpus above is
 * evidence, this block is coverage.
 */
describe("derived variants", () => {
  const logs = load("eth_getLogs.json");
  const receipt = load("eth_getTransactionReceipt.json");
  const call = load("eth_call_decimals.json");

  const firstResult = (corpus: CorpusFile) => answered(corpus)[0][1].result;

  it("collapses a reordered log array", () => {
    const original = firstResult(logs) as unknown[];
    expect(original.length).toBeGreaterThan(1);

    const reversed = [...original].reverse();

    expect(hashRpcResult(reversed, "eth_getLogs")).toBe(hashRpcResult(original, "eth_getLogs"));
  });

  it("collapses differing hex case", () => {
    const original = firstResult(receipt);

    expect(hashRpcResult(upperCaseHex(original), "eth_getTransactionReceipt")).toBe(
      hashRpcResult(original, "eth_getTransactionReceipt")
    );
  });

  it("collapses leading zeros on quantity fields", () => {
    const original = firstResult(receipt) as Record<string, unknown>;
    const padded = { ...original };
    for (const field of ["blockNumber", "gasUsed", "cumulativeGasUsed", "transactionIndex", "status"]) {
      const value = original[field];
      if (typeof value === "string" && value.startsWith("0x")) {
        padded[field] = `0x${"0".repeat(8)}${value.slice(2)}`;
      }
    }

    expect(hashRpcResult(padded, "eth_getTransactionReceipt")).toBe(
      hashRpcResult(original, "eth_getTransactionReceipt")
    );
  });

  it("does NOT collapse a stripped DATA value", () => {
    // The guard that matters most. eth_call returns DATA: this real response is USDC's
    // decimals(), a uint8 ABI-encoded as a padded 32-byte word. If normalization stripped
    // its leading zeros the way it strips a QUANTITY's, that value would collide with a
    // bare 0x6 and two different answers would hash identically.
    const original = firstResult(call) as string;
    expect(original).toMatch(/^0x0{60,}[0-9a-f]+$/i);

    const stripped = `0x${original.slice(2).replace(/^0+/, "")}`;

    expect(hashRpcResult(stripped, "eth_call")).not.toBe(hashRpcResult(original, "eth_call"));
  });

  it("does NOT collapse a changed log topic", () => {
    const original = firstResult(logs) as Record<string, unknown>[];
    const altered = original.map((entry, index) =>
      index === 0 ? { ...entry, topics: [`0x${"f".repeat(64)}`] } : entry
    );

    expect(hashRpcResult(altered, "eth_getLogs")).not.toBe(hashRpcResult(original, "eth_getLogs"));
  });
});

function upperCaseHex(value: unknown): unknown {
  if (typeof value === "string") return /^0x[0-9a-f]*$/i.test(value) ? value.toUpperCase() : value;
  if (Array.isArray(value)) return value.map(upperCaseHex);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>).map(([key, entry]) => [key, upperCaseHex(entry)])
    );
  }
  return value;
}
