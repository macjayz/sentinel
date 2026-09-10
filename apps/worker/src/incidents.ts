import { SentinelEvent, ThreatAssessment } from "@sentinel/shared";

export type IncidentFingerprint = {
  key: string;
  title: string;
  description: string;
  affectedEndpoint: string;
  attackerIp?: string;
};

export function fingerprintIncident(
  event: SentinelEvent,
  assessment: ThreatAssessment
): IncidentFingerprint | null {
  if (assessment.score < 25) return null;

  const endpoint = `${event.request.method} ${event.request.route ?? event.request.path}`;
  const signalNames = new Set(assessment.signals.map((signal) => signal.name));

  if (signalNames.has("auth_failure") && event.request.ip) {
    return {
      key: `${event.projectId}:credential_stuffing:${endpoint}`,
      title: `Potential credential stuffing on ${endpoint}`,
      description: "Repeated authentication failures were observed against the same endpoint.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  // Content-aware RPC findings come first: they name an exact defect in what the provider
  // returned, which is always a more useful incident than a rate or latency heuristic that
  // the same event may also trip.
  if (signalNames.has("provider_disagreement")) {
    const method = event.evmRpc?.method ?? endpoint;
    return {
      key: `${event.projectId}:provider_disagreement:${method}`,
      title: `Providers disagree on ${method}`,
      description:
        "Endpoints returned different results for the same call at the same block height, which is either a provider bug or an unpropagated reorg.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("reorg_lag")) {
    const provider = providerLabel(event);
    return {
      key: `${event.projectId}:reorg_lag:${event.evmRpc?.endpointHash ?? provider}`,
      title: `Reorg lag on ${provider}`,
      description: "This provider is still serving a block its peers have already abandoned.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("log_range_disagreement")) {
    const method = event.evmRpc?.method ?? endpoint;
    return {
      key: `${event.projectId}:log_range_disagreement:${method}`,
      title: `Log ranges differ between providers on ${method}`,
      description: "Endpoints returned different log sets at the same height, most often a silently truncated range.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("receipt_disappeared")) {
    const provider = providerLabel(event);
    return {
      key: `${event.projectId}:receipt_disappeared:${provider}`,
      title: `Transaction receipt disappeared on ${provider}`,
      description: "This provider returned null for a transaction it previously reported as mined.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("stale_head_stalled") || signalNames.has("stale_head_lagging")) {
    const provider = providerLabel(event);
    return {
      key: `${event.projectId}:stale_head:${event.evmRpc?.endpointHash ?? provider}`,
      title: `Stale chain head on ${provider}`,
      description: "This provider is answering successfully while serving an outdated chain head.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("rpc_error_in_body")) {
    const method = event.evmRpc?.method ?? endpoint;
    return {
      key: `${event.projectId}:rpc_error_in_body:${method}`,
      title: `Errors returned inside 200 responses on ${method}`,
      description: "This provider is returning JSON-RPC errors in responses that report transport success.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("empty_data_regression")) {
    const method = event.evmRpc?.method ?? endpoint;
    return {
      key: `${event.projectId}:empty_data_regression:${method}`,
      title: `Empty data returned by ${method}`,
      description: "A call that previously returned data now returns empty data at a later block.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("suspected_log_truncation")) {
    const provider = providerLabel(event);
    return {
      key: `${event.projectId}:log_truncation:${provider}`,
      title: `Suspected log truncation on ${provider}`,
      description: "Log queries keep returning exactly the same result count, suggesting a silently capped page.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  // Web3-specific signals are checked before the generic rate_anomaly signal: a flood of calls to
  // one RPC method from one IP always also trips the generic per-IP rate check, and the more
  // specific category is the more useful incident title.
  if (signalNames.has("tx_burst")) {
    const wallet = shortenAddress(event.evmRpc?.walletAddress);
    return {
      key: `${event.projectId}:tx_burst:${event.evmRpc?.walletAddress ?? endpoint}`,
      title: `Transaction burst from wallet ${wallet}`,
      description: "Wallet transaction volume spiked far above its historical baseline.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("rpc_flooding")) {
    return {
      key: `${event.projectId}:rpc_flooding:${event.evmRpc?.method ?? endpoint}`,
      title: `RPC flooding on ${event.evmRpc?.method ?? endpoint}`,
      description: "This method is being called far more often than normal from a single source.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  // More specific than provider_degradation, which reports the latency half of the same
  // symptom, so it is checked first.
  if (signalNames.has("provider_throttling") || signalNames.has("soft_throttling")) {
    const provider = providerLabel(event);
    const soft = signalNames.has("soft_throttling") && !signalNames.has("provider_throttling");
    return {
      key: `${event.projectId}:${soft ? "soft_throttling" : "provider_throttling"}:${
        event.evmRpc?.endpointHash ?? provider
      }`,
      title: soft ? `Suspected silent throttling on ${provider}` : `Rate limiting from ${provider}`,
      description: soft
        ? "Latency and answer quality degraded together while every response still reported success."
        : "This provider is rate limiting an abnormal share of recent requests.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("provider_degradation")) {
    const provider = event.evmRpc?.provider ?? "unknown provider";
    return {
      key: `${event.projectId}:provider_degradation:${provider}`,
      title: `RPC provider degradation: ${provider}`,
      description: "This RPC provider's latency has degraded well beyond its recent baseline.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("provider_failures")) {
    const provider = event.evmRpc?.provider ?? "unknown provider";
    return {
      key: `${event.projectId}:provider_failures:${provider}`,
      title: `Elevated RPC failures: ${provider}`,
      description: "This RPC provider is failing an abnormal share of recent requests.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("rate_anomaly") && event.request.ip) {
    return {
      key: `${event.projectId}:request_spike:${endpoint}`,
      title: `Request spike on ${endpoint}`,
      description: "Request volume exceeded the heuristic threshold for a single source.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  if (signalNames.has("sensitive_rpc")) {
    return {
      key: `${event.projectId}:sensitive_rpc:${event.evmRpc?.method ?? endpoint}`,
      title: `Sensitive EVM RPC activity on ${endpoint}`,
      description: "Sensitive JSON-RPC methods were observed and grouped for review.",
      affectedEndpoint: endpoint,
      attackerIp: event.request.ip
    };
  }

  return {
    key: `${event.projectId}:heuristic_risk:${endpoint}`,
    title: `Elevated API risk on ${endpoint}`,
    description: assessment.signals.map((signal) => signal.reason).join("; "),
    affectedEndpoint: endpoint,
    attackerIp: event.request.ip
  };
}

function providerLabel(event: SentinelEvent): string {
  return event.evmRpc?.provider ?? "unknown provider";
}

function shortenAddress(address?: string): string {
  if (!address) return "unknown wallet";
  return address.length > 10 ? `${address.slice(0, 6)}...${address.slice(-4)}` : address;
}
