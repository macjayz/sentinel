import { createHash } from "node:crypto";

/**
 * RPC result capture primitives.
 *
 * Every content-aware detector (see docs/detectors.md) depends on being able to answer
 * "did these two responses say the same thing?" without storing raw chain state. That
 * reduces to normalizing a JSON-RPC result into a canonical form and hashing it.
 *
 * Normalization has to be exactly as aggressive as JSON-RPC's own ambiguity and no more.
 * Too little and honest providers look like they disagree over formatting; too much and
 * genuinely different values collide into the same hash and real disagreement goes unseen.
 */

export type ResultShape = "null" | "empty_array" | "empty_data" | "value" | "error_in_body";

export type BlockTag = string;

/**
 * Methods whose top-level result is an EIP-1474 QUANTITY.
 *
 * This distinction is load-bearing. QUANTITY is minimally encoded (`0x1b4`), DATA is
 * byte-aligned and keeps its leading zeros (`0x000...01`). Stripping zeros from DATA
 * would make `eth_call` returning uint256(1) collide with a bare `0x1`, so zero-stripping
 * is only ever applied where the spec says the value is a QUANTITY.
 */
const QUANTITY_RESULT_METHODS = new Set([
  "eth_blockNumber",
  "eth_getBalance",
  "eth_getTransactionCount",
  "eth_gasPrice",
  "eth_maxPriorityFeePerGas",
  "eth_estimateGas",
  "eth_chainId",
  "eth_protocolVersion",
  "eth_getBlockTransactionCountByNumber",
  "eth_getBlockTransactionCountByHash"
]);

/** Object keys that carry a QUANTITY wherever they appear in a result. */
const QUANTITY_FIELDS = new Set([
  "blocknumber",
  "blocktimestamp",
  "timestamp",
  "gas",
  "gasused",
  "cumulativegasused",
  "gasprice",
  "effectivegasprice",
  "maxfeepergas",
  "maxpriorityfeepergas",
  "basefeepergas",
  "blobgasused",
  "excessblobgas",
  "blobgasprice",
  "value",
  "nonce",
  "transactionindex",
  "logindex",
  "status",
  "type",
  "chainid",
  "size",
  "difficulty",
  "totaldifficulty",
  "v",
  "yparity"
]);

/**
 * Methods whose result is an array whose order is not guaranteed across providers.
 * Canonical ordering is (blockNumber, logIndex) — the chain's own ordering.
 */
const UNORDERED_ARRAY_METHODS = new Set(["eth_getLogs", "eth_getFilterLogs", "eth_getFilterChanges"]);

/**
 * Where in the params list each method carries its block tag.
 * `-1` means the method does not take one.
 */
const BLOCK_TAG_PARAM_INDEX: Record<string, number> = {
  eth_call: 1,
  eth_getBalance: 1,
  eth_getCode: 1,
  eth_getTransactionCount: 1,
  eth_getStorageAt: 2,
  eth_estimateGas: 1,
  eth_getBlockByNumber: 0,
  eth_getBlockTransactionCountByNumber: 0,
  eth_getProof: 2
};

/**
 * Default compute-unit weights, used for cost accounting (detector D6).
 *
 * These are order-of-magnitude defaults modelled on published provider pricing. Providers
 * change their weights, and they differ between providers, so treat these as a starting
 * point to be overridden per deployment rather than as authoritative billing figures.
 */
export const DEFAULT_METHOD_COST_UNITS: Record<string, number> = {
  eth_chainId: 0,
  eth_blockNumber: 10,
  eth_getTransactionReceipt: 15,
  eth_getBlockByNumber: 16,
  eth_getStorageAt: 17,
  eth_getTransactionByHash: 17,
  eth_getBalance: 19,
  eth_getCode: 19,
  eth_gasPrice: 19,
  eth_call: 26,
  eth_getTransactionCount: 26,
  eth_getLogs: 75,
  eth_estimateGas: 87,
  eth_sendRawTransaction: 250
};

/** Cost weight for a method, or `undefined` when the method is not in the table. */
export function methodCostUnits(
  method: string,
  table: Record<string, number> = DEFAULT_METHOD_COST_UNITS
): number | undefined {
  return table[method];
}

/**
 * Nominal block time in milliseconds, used by the stale-head detector (D1) to decide how
 * long a head may stand still before it is suspicious. Unknown chains fall back to a
 * measured median at the call site rather than to a global constant.
 */
export const CHAIN_BLOCK_TIME_MS: Record<string, number> = {
  "1": 12_000, // Ethereum mainnet
  "10": 2_000, // Optimism
  "137": 2_000, // Polygon PoS
  "8453": 2_000, // Base
  "42161": 250, // Arbitrum One
  "11155111": 12_000 // Sepolia
};

export function chainBlockTimeMs(chainId: string | undefined): number | undefined {
  if (!chainId) return undefined;
  return CHAIN_BLOCK_TIME_MS[chainId];
}

/**
 * Hash of an RPC endpoint URL.
 *
 * Provider URLs embed API keys (`https://eth-mainnet.g.alchemy.com/v2/<KEY>`), so the URL
 * itself must never be persisted or transmitted. This lets two endpoints be told apart
 * without Sentinel ever holding the credential.
 */
export function hashEndpoint(url: string): string {
  return createHash("sha256").update(url).digest("hex").slice(0, 32);
}

/** Canonical hash of a JSON-RPC result, for same-height comparison across providers. */
export function hashRpcResult(result: unknown, method?: string): string {
  const normalized = normalizeRpcResult(result, method);
  return createHash("sha256").update(JSON.stringify(normalized) ?? "undefined").digest("hex").slice(0, 32);
}

/**
 * Reduce a JSON-RPC result to canonical form:
 *
 * - object keys sorted, so key order never affects the hash
 * - `undefined`-valued keys dropped; explicit `null` preserved (they mean different things)
 * - hex lowercased everywhere (hex is case-insensitive, so case is never a real difference)
 * - leading zeros stripped only from values the spec defines as QUANTITY
 * - provider-order-dependent arrays (logs) sorted into chain order
 */
export function normalizeRpcResult(result: unknown, method?: string): unknown {
  const rootIsQuantity = method ? QUANTITY_RESULT_METHODS.has(method) : false;
  const normalized = normalizeValue(result, rootIsQuantity);

  if (method && UNORDERED_ARRAY_METHODS.has(method) && Array.isArray(normalized)) {
    return sortLogs(normalized);
  }

  return normalized;
}

function normalizeValue(value: unknown, isQuantity: boolean): unknown {
  if (value === null || value === undefined) return value ?? null;

  if (typeof value === "string") {
    return normalizeString(value, isQuantity);
  }

  if (typeof value === "number" || typeof value === "boolean") return value;

  if (Array.isArray(value)) {
    return value.map((entry) => normalizeValue(entry, false));
  }

  if (typeof value === "object") {
    const source = value as Record<string, unknown>;
    const out: Record<string, unknown> = {};

    for (const key of Object.keys(source).sort()) {
      const child = source[key];
      if (child === undefined) continue;
      out[key] = normalizeValue(child, QUANTITY_FIELDS.has(key.toLowerCase()));
    }

    return out;
  }

  return value;
}

function normalizeString(value: string, isQuantity: boolean): string {
  if (!isHexString(value)) return value;

  const lowered = value.toLowerCase();
  if (!isQuantity) return lowered;

  const digits = lowered.slice(2).replace(/^0+/, "");
  return digits.length === 0 ? "0x0" : `0x${digits}`;
}

function isHexString(value: string): boolean {
  return /^0x[0-9a-f]*$/i.test(value);
}

/**
 * Order logs the way the chain does: by block, then by position within the block.
 * Entries missing either field keep their relative order so the sort stays stable.
 */
function sortLogs(logs: unknown[]): unknown[] {
  return [...logs].sort((left, right) => {
    const leftBlock = hexToNumber(readField(left, "blockNumber"));
    const rightBlock = hexToNumber(readField(right, "blockNumber"));
    if (leftBlock !== rightBlock) return leftBlock - rightBlock;

    const leftIndex = hexToNumber(readField(left, "logIndex"));
    const rightIndex = hexToNumber(readField(right, "logIndex"));
    return leftIndex - rightIndex;
  });
}

function readField(value: unknown, key: string): unknown {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  return (value as Record<string, unknown>)[key];
}

function hexToNumber(value: unknown): number {
  if (typeof value !== "string" || !isHexString(value)) return Number.MAX_SAFE_INTEGER;
  const parsed = Number.parseInt(value, 16);
  return Number.isNaN(parsed) ? Number.MAX_SAFE_INTEGER : parsed;
}

/**
 * Classify a response so silent failures (D3) are visible without storing the result.
 *
 * `empty_array` and `null` are recorded as facts, not as failures — emptiness is often
 * correct. D3 only ever fires on a *change* or a disagreement, never on emptiness alone.
 */
export function classifyResultShape(result: unknown, errorInBody = false): ResultShape {
  if (errorInBody) return "error_in_body";
  if (result === null || result === undefined) return "null";
  if (Array.isArray(result) && result.length === 0) return "empty_array";
  // A bare `0x` is an empty DATA return. For eth_call it means the call reverted or hit a
  // contract that isn't there — a different failure signature from a null result, and one
  // that reads as an ordinary success to anything looking only at status codes.
  if (result === "0x") return "empty_data";
  return "value";
}

/**
 * Number of entries in an array result, used to spot silently truncated pages (D3).
 * Non-array results have no count rather than a count of zero.
 */
export function resultCount(result: unknown): number | undefined {
  return Array.isArray(result) ? result.length : undefined;
}

/** The block tag a call was made against, as written by the caller. */
export function extractBlockTag(method: string, params: unknown): BlockTag | undefined {
  const index = BLOCK_TAG_PARAM_INDEX[method];
  if (index === undefined || !Array.isArray(params)) return undefined;

  const tag = params[index];
  return typeof tag === "string" ? tag : undefined;
}

/**
 * The concrete height a call resolved against.
 *
 * Prefers a height carried by the result itself, since that is what the provider actually
 * answered from; falls back to a numeric block tag in the request.
 */
export function extractBlockNumber(method: string, params: unknown, result: unknown): string | undefined {
  const fromResult = readField(result, "blockNumber");
  if (typeof fromResult === "string" && isHexString(fromResult)) {
    return String(Number.parseInt(fromResult, 16));
  }

  if (QUANTITY_RESULT_METHODS.has(method) && method === "eth_blockNumber" && typeof result === "string") {
    return String(Number.parseInt(result, 16));
  }

  const tag = extractBlockTag(method, params);
  if (tag && isHexString(tag)) return String(Number.parseInt(tag, 16));

  return undefined;
}

/** The block hash a result was served from, when the response carries one (reorg tracking, D4). */
export function extractBlockHash(result: unknown): string | undefined {
  const direct = readField(result, "blockHash");
  if (typeof direct === "string" && /^0x[0-9a-f]{64}$/i.test(direct)) return direct.toLowerCase();

  const asBlock = readField(result, "hash");
  const hasParent = readField(result, "parentHash");
  if (hasParent && typeof asBlock === "string" && /^0x[0-9a-f]{64}$/i.test(asBlock)) {
    return asBlock.toLowerCase();
  }

  return undefined;
}

/** A JSON-RPC error object returned inside an HTTP 200 body. */
export function extractRpcError(body: unknown): { code?: number; message?: string } | undefined {
  const error = readField(body, "error");
  if (!error || typeof error !== "object") return undefined;

  const code = readField(error, "code");
  const message = readField(error, "message");

  return {
    code: typeof code === "number" ? code : undefined,
    message: typeof message === "string" ? message : undefined
  };
}

/**
 * Methods whose answer at a fixed block height is deterministic, and which are therefore
 * safe to replay against another endpoint for comparison (detector D2).
 *
 * This is an allowlist, never a denylist: shadowing `eth_gasPrice` or `eth_estimateGas`
 * would compare two legitimately different answers and report every sample as a
 * disagreement.
 */
export const VERIFIABLE_METHODS = new Set([
  "eth_call",
  "eth_getBalance",
  "eth_getCode",
  "eth_getStorageAt",
  "eth_getTransactionCount",
  "eth_getLogs",
  "eth_getTransactionReceipt",
  "eth_getBlockByNumber"
]);

/** Block tags whose result is not fixed, and so can never be compared across endpoints. */
const UNPINNABLE_TAGS = new Set(["pending"]);

export function isVerifiableMethod(method: string): boolean {
  return VERIFIABLE_METHODS.has(method);
}

export function blockTagParamIndex(method: string): number | undefined {
  return BLOCK_TAG_PARAM_INDEX[method];
}

/**
 * Rewrite a call's block tag to a concrete height so two endpoints can be asked exactly
 * the same question.
 *
 * This is the single most important step in cross-provider verification. Comparing a
 * `latest` response from one endpoint against a `latest` response from another measures
 * how far apart their heads are, not whether they disagree — and at any real head skew
 * that produces a false positive on essentially every sample.
 *
 * Returns `undefined` when the call cannot be pinned, in which case it must not be
 * shadowed at all.
 */
export function pinBlockTag(method: string, params: unknown, blockNumber: string): unknown[] | undefined {
  if (!Array.isArray(params)) return undefined;

  const height = Number(blockNumber);
  if (!Number.isFinite(height) || height < 0) return undefined;
  const hexHeight = `0x${height.toString(16)}`;

  // Log queries carry their range inside a filter object rather than as a positional tag.
  if (method === "eth_getLogs" || method === "eth_getFilterLogs") {
    const filter = params[0];
    if (!filter || typeof filter !== "object" || Array.isArray(filter)) return undefined;

    const source = filter as Record<string, unknown>;
    if (typeof source.blockHash === "string") return [...params];

    const pinnedFilter: Record<string, unknown> = { ...source };
    for (const key of ["fromBlock", "toBlock"]) {
      const value = source[key];
      if (value === undefined) continue;
      if (typeof value !== "string") return undefined;
      if (UNPINNABLE_TAGS.has(value)) return undefined;
      if (value === "latest" || value === "safe" || value === "finalized") pinnedFilter[key] = hexHeight;
    }

    return [pinnedFilter, ...params.slice(1)];
  }

  const index = blockTagParamIndex(method);

  // A method with no block tag is already pinned by its own argument — a receipt is
  // identified by transaction hash, not by height.
  if (index === undefined) return [...params];

  const tag = params[index];
  if (typeof tag === "string" && UNPINNABLE_TAGS.has(tag)) return undefined;

  const pinned = [...params];
  pinned[index] = hexHeight;
  return pinned;
}

/**
 * JSON-RPC error codes providers use to mean "you are being rate limited".
 * Codes vary between providers; the message check below covers the rest.
 */
const THROTTLE_ERROR_CODES = new Set([429, -32005, -32007, -32029]);

/**
 * Provider phrasings for rate limiting. Deliberately narrow: a loose pattern here would
 * swallow ordinary execution errors like "gas limit exceeded" and turn every reverted
 * call into a throttling finding.
 */
const THROTTLE_MESSAGE_PATTERN =
  /rate.?limit|too many requests|throttl|quota|capacity exceeded|request limit|compute unit/i;

/**
 * Whether a response carries a rate-limiting signature (detector D5).
 *
 * Covers the clean case (HTTP 429) and the case that actually matters: throttling
 * delivered as a JSON-RPC error inside an HTTP 200, where nothing watching status codes
 * will ever see it.
 */
export function isThrottleSignature(
  statusCode: number | undefined,
  rpcErrorCode: number | undefined,
  rpcErrorMessage: string | undefined
): boolean {
  if (statusCode === 429) return true;
  if (rpcErrorCode !== undefined && THROTTLE_ERROR_CODES.has(rpcErrorCode)) return true;
  return Boolean(rpcErrorMessage && THROTTLE_MESSAGE_PATTERN.test(rpcErrorMessage));
}
