import { chainBlockTimeMs } from "./rpc.js";
import type { SentinelEvent, ThreatSignal } from "./index.js";

/**
 * Content-aware RPC detectors D1, D3 and D6 (see docs/detectors.md).
 *
 * These are pure functions over an event plus context the worker gathers from storage, so
 * every firing condition is testable without a database. They deliberately do not fire on
 * absence alone: an empty result, a null receipt and a slow head are all frequently
 * correct. Each rule below fires on a *change* or a *comparison*, never on emptiness.
 */

export type DetectorThresholds = {
  /** How many block times a head may stand still before it is considered stalled. */
  staleHeadBlockTimeMultiplier: number;
  /** How far behind the fastest endpoint a head may fall before it is considered lagging. */
  maxHeadLagBlocks: number;
  /** Minimum head observations before D1 will judge an endpoint at all. */
  minHeadObservations: number;
  /** How often a result count must recur at the same ceiling to read as a page limit. */
  pageLimitMinHits: number;
  /** Reorg depth at or above which a reorg is worth raising rather than just recording. */
  reorgAlertMinDepth: number;
  /** How long an endpoint may keep serving a superseded block before it counts as lag. */
  reorgConvergenceLagMs: number;
  /** Share of recent requests carrying a throttle signature before it is worth reporting. */
  throttleRateThreshold: number;
  /** Minimum requests behind a rate before D5 will judge an endpoint. */
  minThrottleSample: number;
  /** Latency multiplier over baseline that counts as a cliff. */
  softThrottleLatencyMultiplier: number;
  /** How much worse recent result quality must be than baseline to count as degradation. */
  softThrottleDegradationMultiplier: number;
};

export const DEFAULT_DETECTOR_THRESHOLDS: DetectorThresholds = {
  staleHeadBlockTimeMultiplier: 3,
  maxHeadLagBlocks: 3,
  minHeadObservations: 3,
  pageLimitMinHits: 3,
  reorgAlertMinDepth: 2,
  reorgConvergenceLagMs: 6_000,
  throttleRateThreshold: 0.05,
  minThrottleSample: 20,
  softThrottleLatencyMultiplier: 3,
  softThrottleDegradationMultiplier: 2
};

export type StaleHeadContext = {
  /** Highest head this endpoint reported in the window. */
  endpointHeadBlockNumber?: number;
  /** Milliseconds since this endpoint's head last advanced. */
  endpointHeadStalledMs?: number;
  /** Head observations from this endpoint in the window. */
  endpointHeadObservations?: number;
  /** Highest head reported by any endpoint on this chain in the window. */
  chainHeadBlockNumber?: number;
  /** Median block time measured from observations, for chains not in the static table. */
  measuredBlockTimeMs?: number;
};

export type SilentFailureContext = {
  /** This endpoint previously returned a non-null result for the same target (e.g. tx hash). */
  priorNonNullForSameTarget?: boolean;
  /** This endpoint previously returned data for identical params at an earlier block. */
  priorDataForSameCall?: boolean;
  /** Largest result count seen from this endpoint for this method. */
  endpointMaxResultCount?: number;
  /** How many times that maximum recurred — a repeated hard ceiling reads as a page limit. */
  endpointMaxResultCountHits?: number;
};

export type CostWasteContext = {
  /** Identical (method, params, block) already recorded for this project in the same block. */
  duplicateCallCount?: number;
  /** Cost units already spent on those duplicates. */
  duplicateCostUnits?: number;
};

/** Block tags whose results are expected to lag the chain head, and must not trip D1. */
const LAGGING_BLOCK_TAGS = new Set(["finalized", "safe", "earliest"]);

const RECEIPT_METHODS = new Set(["eth_getTransactionReceipt", "eth_getTransactionByHash"]);
const CALL_METHODS = new Set(["eth_call", "eth_getCode"]);
const LOG_METHODS = new Set(["eth_getLogs", "eth_getFilterLogs"]);

/**
 * D1 — stale head.
 *
 * Two independent conditions: a head that has stopped advancing while the endpoint is
 * still answering, and a head that trails the fastest endpoint on the same chain.
 */
export function detectStaleHead(
  event: SentinelEvent,
  context: StaleHeadContext = {},
  thresholds: DetectorThresholds = DEFAULT_DETECTOR_THRESHOLDS
): ThreatSignal[] {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return [];

  // A call pinned to a past block, or explicitly asking for finalized state, is supposed
  // to return old data. Only head-tracking calls say anything about staleness.
  const tag = event.evmRpc.blockTag;
  if (tag && (LAGGING_BLOCK_TAGS.has(tag) || tag.startsWith("0x"))) return [];

  // Sparse traffic produces sparse samples; judging an endpoint on one or two
  // observations produces noise rather than findings.
  if ((context.endpointHeadObservations ?? 0) < thresholds.minHeadObservations) return [];

  const signals: ThreatSignal[] = [];
  const blockTime = chainBlockTimeMs(event.evmRpc.chainId) ?? context.measuredBlockTimeMs;

  if (blockTime && context.endpointHeadStalledMs !== undefined) {
    const limit = blockTime * thresholds.staleHeadBlockTimeMultiplier;
    if (context.endpointHeadStalledMs > limit) {
      signals.push({
        name: "stale_head_stalled",
        weight: 30,
        reason: `Provider is still answering but its chain head has not advanced for ${Math.round(
          context.endpointHeadStalledMs / 1000
        )}s, over ${thresholds.staleHeadBlockTimeMultiplier}x this chain's block time`
      });
    }
  }

  const head = context.endpointHeadBlockNumber;
  const chainHead = context.chainHeadBlockNumber;
  if (head !== undefined && chainHead !== undefined) {
    const lag = chainHead - head;
    if (lag > thresholds.maxHeadLagBlocks) {
      signals.push({
        name: "stale_head_lagging",
        weight: 26,
        reason: `Provider's chain head is ${lag} blocks behind the furthest-ahead endpoint on this chain`
      });
    }
  }

  return signals;
}

/**
 * D3 — silent failure.
 *
 * Responses that arrive as successes but carry no usable answer. Every rule except the
 * explicit in-body error is comparative, because emptiness on its own is usually correct.
 */
export function detectSilentFailure(
  event: SentinelEvent,
  context: SilentFailureContext = {},
  thresholds: DetectorThresholds = DEFAULT_DETECTOR_THRESHOLDS
): ThreatSignal[] {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return [];

  const { method, resultShape, resultCount: count } = event.evmRpc;
  const signals: ThreatSignal[] = [];

  // Not comparative: a JSON-RPC error object is the provider stating it failed, while the
  // transport reported success. Nothing that reads status codes will ever see this.
  if (resultShape === "error_in_body") {
    const code = event.evmRpc.rpcErrorCode;
    signals.push({
      name: "rpc_error_in_body",
      weight: 28,
      reason: `Provider returned HTTP ${event.response.statusCode} carrying a JSON-RPC error${
        code === undefined ? "" : ` (code ${code})`
      }`
    });
  }

  if (RECEIPT_METHODS.has(method) && resultShape === "null" && context.priorNonNullForSameTarget) {
    signals.push({
      name: "receipt_disappeared",
      weight: 32,
      reason: `${method} now returns null for a transaction this same provider previously reported as mined`
    });
  }

  if (CALL_METHODS.has(method) && resultShape === "empty_data" && context.priorDataForSameCall) {
    signals.push({
      name: "empty_data_regression",
      weight: 26,
      reason: `${method} returned empty data for a call that previously returned data at an earlier block`
    });
  }

  if (
    LOG_METHODS.has(method) &&
    count !== undefined &&
    count > 0 &&
    context.endpointMaxResultCount === count &&
    (context.endpointMaxResultCountHits ?? 0) >= thresholds.pageLimitMinHits
  ) {
    signals.push({
      name: "suspected_log_truncation",
      weight: 20,
      reason: `${method} returned exactly ${count} results, a ceiling this provider has hit ${context.endpointMaxResultCountHits} times — likely a silently truncated page`
    });
  }

  return signals;
}

/**
 * D6 — cost and waste.
 *
 * Waste is a billing problem, not a threat, so these signals carry zero weight: they are
 * recorded against the event and aggregated for reporting without inflating a threat score
 * or manufacturing an incident.
 */
export function detectCostWaste(event: SentinelEvent, context: CostWasteContext = {}): ThreatSignal[] {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return [];

  // Only provable at a pinned height. Two identical calls either side of a block boundary
  // are legitimate polling, not waste.
  if (!event.evmRpc.blockNumber) return [];

  const duplicates = context.duplicateCallCount ?? 0;
  if (duplicates < 1) return [];

  const spent = context.duplicateCostUnits;

  return [
    {
      name: "duplicate_rpc_call",
      weight: 0,
      reason: `Identical ${event.evmRpc.method} at block ${event.evmRpc.blockNumber} has already been made ${duplicates} time${
        duplicates === 1 ? "" : "s"
      }${spent ? `, costing ${spent} compute units` : ""}`
    }
  ];
}

export type PeerResult = {
  endpointHash?: string;
  provider?: string;
  resultHash: string;
};

export type DisagreementContext = {
  /**
   * Result hashes other endpoints returned for the same call at the same pinned height.
   * Only ever populated from block-pinned verification calls: comparing two `latest`
   * responses measures head skew, not disagreement.
   */
  peerResults?: PeerResult[];
  /** Peers that could not serve the pinned height at all. */
  peersMissingBlock?: number;
};

export type ReorgContext = {
  /** A different block hash previously recorded at this height, from any endpoint. */
  priorBlockHashAtHeight?: string;
  /** Distinct heights in the recent window that have shown more than one hash. */
  reorgDepth?: number;
  /** Another endpoint already reports a different hash at this height. */
  supersededByPeer?: boolean;
  /** How long ago a peer first reported the newer hash. */
  peerConvergenceLagMs?: number;
};

/** Methods whose disagreement almost always means truncation rather than a wrong answer. */
const DISAGREEMENT_LOG_METHODS = new Set(["eth_getLogs", "eth_getFilterLogs"]);

/**
 * D2 — cross-provider disagreement.
 *
 * At equal block height a mismatch is either a provider bug or an unpropagated reorg.
 * Both are worth raising, and neither is visible to anything that only watches status
 * codes and latency.
 *
 * The caller is responsible for only ever supplying peer results from block-pinned calls.
 * A peer that cannot serve the pinned height is not a disagreement — that is a stale head,
 * and D1 is what reports it.
 */
export function detectDisagreement(
  event: SentinelEvent,
  context: DisagreementContext = {}
): ThreatSignal[] {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return [];

  const { method, resultHash, blockNumber } = event.evmRpc;
  if (!resultHash || !blockNumber) return [];

  const peers = context.peerResults ?? [];
  const disagreeing = peers.filter((peer) => peer.resultHash !== resultHash);
  if (disagreeing.length === 0) return [];

  const labels = disagreeing.map((peer) => peer.provider ?? peer.endpointHash ?? "an unnamed endpoint");

  if (DISAGREEMENT_LOG_METHODS.has(method)) {
    return [
      {
        name: "log_range_disagreement",
        weight: 20,
        reason: `${method} at block ${blockNumber} returned a different set of logs than ${labels.join(
          ", "
        )} — most often a silently truncated range rather than a wrong answer`
      }
    ];
  }

  return [
    {
      name: "provider_disagreement",
      weight: 40,
      reason: `${method} at block ${blockNumber} returned a different result than ${labels.join(
        ", "
      )}; at equal height this is a provider bug or an unpropagated reorg`
    }
  ];
}

/**
 * D4 — reorg lag.
 *
 * A hash changing at a height that was already observed is a reorg. Single-block reorgs
 * are ordinary on mainnet and are recorded rather than alerted; what matters is depth, and
 * whether this endpoint is still serving a chain its peers have already abandoned.
 */
export function detectReorgLag(
  event: SentinelEvent,
  context: ReorgContext = {},
  thresholds: DetectorThresholds = DEFAULT_DETECTOR_THRESHOLDS
): ThreatSignal[] {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return [];

  const { blockHash, blockNumber } = event.evmRpc;
  if (!blockHash || !blockNumber) return [];

  const signals: ThreatSignal[] = [];
  const prior = context.priorBlockHashAtHeight;

  if (prior && prior !== blockHash) {
    const depth = context.reorgDepth ?? 1;
    // A one-block reorg is normal chain behaviour. Record it as a signal so it lands in
    // the data, but give it no weight so it cannot manufacture an incident on its own.
    // Kept below the incident threshold on purpose. A reorg is the chain's behaviour, not
    // the provider's fault, so it is recorded and scored but does not raise an incident on
    // its own. The actionable finding is `reorg_lag` below: a provider still serving a
    // chain its peers have already abandoned.
    const alerting = depth >= thresholds.reorgAlertMinDepth;
    signals.push({
      name: "reorg_detected",
      weight: alerting ? 24 : 0,
      reason: `Block ${blockNumber} changed hash${
        depth > 1 ? `, part of a ${depth}-block reorg` : " in a single-block reorg"
      }`
    });
  }

  if (context.supersededByPeer && (context.peerConvergenceLagMs ?? 0) > thresholds.reorgConvergenceLagMs) {
    signals.push({
      name: "reorg_lag",
      weight: 28,
      reason: `Provider is still serving block ${blockNumber} at a hash its peers abandoned ${Math.round(
        (context.peerConvergenceLagMs ?? 0) / 1000
      )}s ago`
    });
  }

  return signals;
}

export type ThrottlingContext = {
  /** Share of recent requests to this endpoint that carried a throttle signature. */
  recentThrottleRate?: number;
  /** Requests behind that rate, so a single throttled call cannot read as 100%. */
  recentRequestCount?: number;
  /** Share of recent results that came back empty or errored rather than as values. */
  recentDegradedResultRate?: number;
  /** The same share over the preceding window, for comparison. */
  baselineDegradedResultRate?: number;
  recentP95LatencyMs?: number;
  baselineP95LatencyMs?: number;
};

/**
 * D5 — throttling as success.
 *
 * The clean case is a 429. The case that matters is a provider quietly degrading under
 * load: latency steps up and results start coming back empty, with every response still
 * reporting success.
 *
 * The soft rule deliberately requires **both** latency degradation and result degradation.
 * A latency cliff on its own is already reported by `provider_degradation`, and firing here
 * as well would just restate it under a second name.
 */
export function detectThrottling(
  event: SentinelEvent,
  context: ThrottlingContext = {},
  thresholds: DetectorThresholds = DEFAULT_DETECTOR_THRESHOLDS
): ThreatSignal[] {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return [];

  const sample = context.recentRequestCount ?? 0;
  if (sample < thresholds.minThrottleSample) return [];

  const throttleRate = context.recentThrottleRate ?? 0;
  if (throttleRate > thresholds.throttleRateThreshold) {
    return [
      {
        name: "provider_throttling",
        weight: 22,
        reason: `${Math.round(throttleRate * 100)}% of recent requests to this provider were rate limited`
      }
    ];
  }

  // Soft throttling: neither half is conclusive alone, so both are required.
  const recentLatency = context.recentP95LatencyMs ?? 0;
  const baselineLatency = context.baselineP95LatencyMs ?? 0;
  const latencyCliff =
    baselineLatency > 0 && recentLatency > baselineLatency * thresholds.softThrottleLatencyMultiplier;

  const recentDegraded = context.recentDegradedResultRate ?? 0;
  const baselineDegraded = context.baselineDegradedResultRate ?? 0;
  const resultsDegraded =
    recentDegraded > 0 &&
    recentDegraded > baselineDegraded * thresholds.softThrottleDegradationMultiplier;

  if (latencyCliff && resultsDegraded) {
    return [
      {
        name: "soft_throttling",
        weight: 26,
        reason: `Provider latency rose to ${Math.round(recentLatency)}ms against a ${Math.round(
          baselineLatency
        )}ms baseline while empty or errored results rose to ${Math.round(
          recentDegraded * 100
        )}% — the signature of throttling delivered as success`
      }
    ];
  }

  return [];
}
