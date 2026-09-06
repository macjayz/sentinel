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

function shortenAddress(address?: string): string {
  if (!address) return "unknown wallet";
  return address.length > 10 ? `${address.slice(0, 6)}...${address.slice(-4)}` : address;
}
