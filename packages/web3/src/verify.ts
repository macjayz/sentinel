import {
  classifyResultShape,
  extractBlockHash,
  extractRpcError,
  hashEndpoint,
  hashRpcResult,
  isVerifiableMethod,
  pinBlockTag,
  type ResultShape
} from "@sentinel/shared";

/**
 * Cross-provider verification (detector D2).
 *
 * A sampled call is replayed against one or more other endpoints at a **pinned block
 * height**, and the normalized results are compared. At equal height a mismatch is either
 * a provider bug or an unpropagated reorg.
 *
 * What is actually being verified: when the original call named a concrete height, this
 * compares answers to exactly that question. When it used `latest`, the height that
 * `latest` resolved to is not recoverable from the response, so verification instead
 * re-probes every endpoint — including the primary — at a freshly resolved height. That
 * measures whether the providers agree, rather than auditing one specific response, and it
 * is the only form of the comparison that is free of head-skew false positives.
 */

export type VerificationEndpoint = {
  rpcUrl: string;
  provider?: string;
};

export type VerificationOptions = {
  /** Endpoints to compare against. */
  endpoints: VerificationEndpoint[];
  /** Fraction of eligible calls to verify. Kept low: every sample costs real requests. */
  sampleRate?: number;
  /** Hard ceiling on outgoing verification calls. Verification must never dominate cost. */
  maxCallsPerMinute?: number;
  /** How long a resolved chain head may be reused as a pin target. */
  headCacheMs?: number;
  timeoutMs?: number;
  random?: () => number;
  now?: () => number;
  fetchImpl?: typeof fetch;
};

export type PeerObservation = {
  endpointHash: string;
  provider?: string;
  resultHash?: string;
  resultShape: ResultShape;
  resultCount?: number;
  blockHash?: string;
  latencyMs: number;
  /**
   * The endpoint could not serve the pinned height. This is a stale head (D1), not a
   * disagreement, and must never be compared as one.
   */
  missingBlock: boolean;
  rpcErrorCode?: number;
  rpcErrorMessage?: string;
};

export type VerificationRun = {
  blockNumber: string;
  pinnedParams: unknown[];
  observations: PeerObservation[];
};

const DEFAULT_SAMPLE_RATE = 0.01;
const DEFAULT_MAX_CALLS_PER_MINUTE = 60;
const DEFAULT_HEAD_CACHE_MS = 2_000;
const DEFAULT_TIMEOUT_MS = 5_000;

/** Provider phrasings for "I don't have that block", which must not read as disagreement. */
const MISSING_BLOCK_PATTERN =
  /not found|missing trie node|unavailable|pruned|unknown block|state.*not available|header not/i;

export class RpcVerifier {
  private readonly sampleRate: number;
  private readonly maxCallsPerMinute: number;
  private readonly headCacheMs: number;
  private readonly timeoutMs: number;
  private readonly random: () => number;
  private readonly now: () => number;
  private readonly fetchImpl: typeof fetch;

  /** Timestamps of recent outgoing verification calls, for the per-minute ceiling. */
  private recentCalls: number[] = [];
  private cachedHead?: { blockNumber: string; at: number };

  constructor(private readonly options: VerificationOptions) {
    this.sampleRate = options.sampleRate ?? DEFAULT_SAMPLE_RATE;
    this.maxCallsPerMinute = options.maxCallsPerMinute ?? DEFAULT_MAX_CALLS_PER_MINUTE;
    this.headCacheMs = options.headCacheMs ?? DEFAULT_HEAD_CACHE_MS;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.random = options.random ?? Math.random;
    this.now = options.now ?? Date.now;
    this.fetchImpl = options.fetchImpl ?? fetch;
  }

  get endpointCount(): number {
    return this.options.endpoints.length;
  }

  /**
   * Whether this call is eligible and selected for verification.
   *
   * Eligibility is an allowlist of deterministic reads, never a denylist: shadowing
   * `eth_gasPrice` would compare two legitimately different answers and report every
   * sample as a disagreement.
   */
  shouldVerify(method: string): boolean {
    if (this.endpointCount === 0) return false;
    if (!isVerifiableMethod(method)) return false;
    if (!this.hasBudget()) return false;
    return this.random() < this.sampleRate;
  }

  /** Remaining budget for a full fan-out, counting one call per endpoint. */
  private hasBudget(): boolean {
    const cutoff = this.now() - 60_000;
    this.recentCalls = this.recentCalls.filter((at) => at > cutoff);
    return this.recentCalls.length + this.endpointCount <= this.maxCallsPerMinute;
  }

  private chargeBudget(calls: number) {
    const at = this.now();
    for (let i = 0; i < calls; i += 1) this.recentCalls.push(at);
  }

  /**
   * Resolve a height to pin against, preferring one the primary response already carries.
   * Returns undefined when no height can be established, in which case the call must not
   * be verified at all — an unpinned comparison is worthless.
   */
  async resolvePinHeight(knownBlockNumber: string | undefined, headSourceUrl?: string) {
    if (knownBlockNumber) return knownBlockNumber;
    if (!headSourceUrl) return undefined;

    const cached = this.cachedHead;
    if (cached && this.now() - cached.at < this.headCacheMs) return cached.blockNumber;

    try {
      const head = await this.call(headSourceUrl, "eth_blockNumber", []);
      if (typeof head.result !== "string") return undefined;

      const blockNumber = String(Number.parseInt(head.result, 16));
      if (!Number.isFinite(Number(blockNumber))) return undefined;

      this.cachedHead = { blockNumber, at: this.now() };
      return blockNumber;
    } catch {
      return undefined;
    }
  }

  /**
   * Ask every configured endpoint the same pinned question.
   *
   * Never throws and never rejects: verification is a side observation and must not be
   * able to fail the caller's real RPC traffic.
   */
  async verify(method: string, params: unknown, blockNumber: string): Promise<VerificationRun | undefined> {
    const pinnedParams = pinBlockTag(method, params, blockNumber);
    if (!pinnedParams) return undefined;
    if (!this.hasBudget()) return undefined;

    this.chargeBudget(this.endpointCount);

    const observations = await Promise.all(
      this.options.endpoints.map((endpoint) => this.probe(endpoint, method, pinnedParams))
    );

    return { blockNumber, pinnedParams, observations };
  }

  private async probe(
    endpoint: VerificationEndpoint,
    method: string,
    params: unknown[]
  ): Promise<PeerObservation> {
    const started = Date.now();
    const endpointHash = hashEndpoint(endpoint.rpcUrl);

    try {
      const body = await this.call(endpoint.rpcUrl, method, params);
      const rpcError = extractRpcError(body);
      const latencyMs = Date.now() - started;

      if (rpcError) {
        return {
          endpointHash,
          provider: endpoint.provider,
          resultShape: "error_in_body",
          latencyMs,
          missingBlock: MISSING_BLOCK_PATTERN.test(rpcError.message ?? ""),
          rpcErrorCode: rpcError.code,
          rpcErrorMessage: rpcError.message
        };
      }

      const result = body.result;
      const shape = classifyResultShape(result);

      return {
        endpointHash,
        provider: endpoint.provider,
        resultHash: result === undefined ? undefined : hashRpcResult(result, method),
        resultShape: shape,
        resultCount: Array.isArray(result) ? result.length : undefined,
        blockHash: extractBlockHash(result),
        latencyMs,
        // A null where the primary had an answer is far more likely to be an endpoint that
        // has not caught up than a claim that the answer is genuinely null.
        missingBlock: shape === "null"
      };
    } catch (error) {
      return {
        endpointHash,
        provider: endpoint.provider,
        resultShape: "error_in_body",
        latencyMs: Date.now() - started,
        missingBlock: false,
        rpcErrorMessage: error instanceof Error ? error.message : "verification_failed"
      };
    }
  }

  private async call(rpcUrl: string, method: string, params: unknown) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await this.fetchImpl(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
        signal: controller.signal
      });

      return (await response.json()) as { result?: unknown; error?: unknown };
    } finally {
      clearTimeout(timer);
    }
  }
}
