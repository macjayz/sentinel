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
