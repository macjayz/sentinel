import pg from "pg";
import { SentinelEvent, ThreatAssessment } from "@sentinel/shared";
import { WorkerConfig } from "./config.js";

const { Pool } = pg;

export function createPool(config: WorkerConfig) {
  return new Pool({ connectionString: config.databaseUrl });
}

export async function countRecentIpRequests(pool: pg.Pool, projectId: string, ip?: string) {
  if (!ip) return 0;
  const result = await pool.query(
    `
    select count(*)::int as count
    from api_events
    where project_id = $1 and ip = $2 and timestamp > now() - interval '1 minute'
    `,
    [projectId, ip]
  );

  return result.rows[0]?.count ?? 0;
}

export async function persistEvent(pool: pg.Pool, event: SentinelEvent, assessment: ThreatAssessment) {
  await pool.query(
    `
    insert into api_events (
      id, project_id, service_name, environment, timestamp, kind, method, path, route, ip,
      user_agent, request_headers, request_query, request_body, status_code, latency_ms,
      body_bytes, auth_present, auth_failed, graphql_operation_name, graphql_operation_type,
      evm_rpc_method, threat_score, threat_severity, threat_signals
    )
    values (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
      $11, $12, $13, $14, $15, $16,
      $17, $18, $19, $20, $21,
      $22, $23, $24, $25
    )
    on conflict (id) do nothing
    `,
    [
      event.id,
      event.projectId,
      event.serviceName,
      event.environment,
      event.timestamp,
      event.kind,
      event.request.method,
      event.request.path,
      event.request.route,
      event.request.ip,
      event.request.userAgent,
      event.request.headers,
      event.request.query,
      event.request.body ?? null,
      event.response.statusCode,
      event.response.latencyMs,
      event.response.bodyBytes ?? null,
      event.request.auth.present,
      event.request.auth.failed,
      event.graphQL?.operationName,
      event.graphQL?.operationType,
      event.evmRpc?.method,
      assessment.score,
      assessment.severity,
      assessment.signals
    ]
  );
}

export async function createIncidentIfNeeded(
  pool: pg.Pool,
  event: SentinelEvent,
  assessment: ThreatAssessment
) {
  if (assessment.score < 25) return;

  await pool.query(
    `
    insert into incidents (event_id, project_id, severity, title, description, signals, status)
    values ($1, $2, $3, $4, $5, $6, 'open')
    on conflict (event_id) do nothing
    `,
    [
      event.id,
      event.projectId,
      assessment.severity,
      `${assessment.severity.toUpperCase()} threat on ${event.request.method} ${event.request.path}`,
      assessment.signals.map((signal) => signal.reason).join("; "),
      assessment.signals
    ]
  );
}
