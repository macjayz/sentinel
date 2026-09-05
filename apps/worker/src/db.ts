import pg from "pg";
import { SentinelEvent, ThreatAssessment, withSpan } from "@sentinel/shared";
import { WorkerConfig } from "./config.js";
import { fingerprintIncident } from "./incidents.js";

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
  await withSpan(
    "sentinel.postgres.persist_event",
    {
      "sentinel.event_id": event.id,
      "sentinel.trace_id": event.traceId,
      "sentinel.project_id": event.projectId
    },
    async () => {
      await pool.query(
        `
    insert into api_events (
      id, trace_id, parent_span_id, project_id, service_name, environment, timestamp, kind, method, path, route, ip,
      user_agent, request_headers, request_query, request_body, status_code, latency_ms,
      body_bytes, auth_present, auth_failed, graphql_operation_name, graphql_operation_type,
      evm_rpc_method, evm_chain_id, evm_provider, wallet_address, contract_address,
      threat_score, threat_severity, threat_signals
    )
    values (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
      $13, $14, $15, $16, $17, $18,
      $19, $20, $21, $22, $23,
      $24, $25, $26, $27, $28,
      $29, $30, $31
    )
    on conflict (id) do nothing
    `,
        [
          event.id,
          event.traceId,
          event.parentSpanId,
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
          toJsonb(event.request.headers),
          toJsonb(event.request.query),
          toJsonb(event.request.body ?? null),
          event.response.statusCode,
          event.response.latencyMs,
          event.response.bodyBytes ?? null,
          event.request.auth.present,
          event.request.auth.failed,
          event.graphQL?.operationName,
          event.graphQL?.operationType,
          event.evmRpc?.method,
          event.evmRpc?.chainId,
          event.evmRpc?.provider,
          event.evmRpc?.walletAddress,
          event.evmRpc?.contractAddress,
          assessment.score,
          assessment.severity,
          toJsonb(assessment.signals)
        ]
      );
    }
  );
}

export async function createIncidentIfNeeded(
  pool: pg.Pool,
  event: SentinelEvent,
  assessment: ThreatAssessment
) {
  const fingerprint = fingerprintIncident(event, assessment);
  if (!fingerprint) return;

  const client = await pool.connect();

  try {
    await client.query("begin");
    let incidentId: string | null = null;
    let isNewIncident = false;

    const existing = await client.query(
      `
      select id, attacker_ips
      from incidents
      where incident_key = $1 and status in ('open', 'acknowledged')
      for update
      `,
      [fingerprint.key]
    );

    if (existing.rowCount && existing.rows[0]) {
      incidentId = existing.rows[0].id;
      const attackerIps = mergeIps(existing.rows[0].attacker_ips, fingerprint.attackerIp);
      await client.query(
        `
        update incidents
        set severity = $2,
            description = $3,
            signals = $4,
            attacker_ips = $5,
            request_count = request_count + 1,
            started_at = least(started_at, $6),
            last_seen_at = greatest(last_seen_at, $6)
        where id = $1
        `,
        [
          existing.rows[0].id,
          assessment.severity,
          fingerprint.description,
          toJsonb(assessment.signals),
          JSON.stringify(attackerIps),
          event.timestamp
        ]
      );
    } else {
      const created = await client.query(
        `
        insert into incidents (
          event_id, incident_key, project_id, severity, title, description, signals,
          affected_endpoint, attacker_ips, request_count, started_at, last_seen_at, status
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, 1, $10, $10, 'open')
        on conflict (incident_key) do nothing
        returning id
        `,
        [
          event.id,
          fingerprint.key,
          event.projectId,
          assessment.severity,
          fingerprint.title,
          fingerprint.description,
          toJsonb(assessment.signals),
          fingerprint.affectedEndpoint,
          JSON.stringify(mergeIps([], fingerprint.attackerIp)),
          event.timestamp
        ]
      );
      incidentId = created.rows[0]?.id ?? null;
      isNewIncident = Boolean(incidentId);
    }

    if (incidentId && isNewIncident && shouldQueueAlertDelivery(assessment.severity)) {
      await client.query(
        `
        insert into alert_deliveries (incident_id, destination_id, project_id, status)
        select $1, id, project_id, 'queued'
        from alert_destinations
        where project_id = $2 and enabled = true
        `,
        [incidentId, event.projectId]
      );
    }

    await client.query("commit");
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

const MAX_ALERT_DELIVERY_ATTEMPTS = 5;

export type AlertDeliveryDetails = {
  id: string;
  attempts: number;
  destination_url: string;
  destination_name: string;
  incident_id: string;
  title: string;
  severity: string;
  description: string;
  affected_endpoint: string;
  attacker_ips: string[];
  request_count: number;
  started_at: string;
};

export async function claimAlertDeliveries(pool: pg.Pool, limit = 10): Promise<AlertDeliveryDetails[]> {
  const claimed = await pool.query(
    `
    update alert_deliveries
    set status = 'sending'
    where id in (
      select id
      from alert_deliveries
      where status = 'queued' and next_attempt_at <= now()
      order by created_at
      limit $1
      for update skip locked
    )
    returning id
    `,
    [limit]
  );

  const ids = claimed.rows.map((row) => row.id);
  if (ids.length === 0) return [];

  const details = await pool.query(
    `
    select deliveries.id, deliveries.attempts,
           destinations.url as destination_url, destinations.name as destination_name,
           incidents.id as incident_id, incidents.title, incidents.severity, incidents.description,
           incidents.affected_endpoint, incidents.attacker_ips, incidents.request_count, incidents.started_at
    from alert_deliveries deliveries
    join alert_destinations destinations on destinations.id = deliveries.destination_id
    join incidents on incidents.id = deliveries.incident_id
    where deliveries.id = any($1::uuid[])
    `,
    [ids]
  );

  return details.rows;
}

export async function markAlertDeliverySucceeded(pool: pg.Pool, deliveryId: string) {
  await pool.query(
    `
    update alert_deliveries
    set status = 'delivered', delivered_at = now(), last_error = null
    where id = $1
    `,
    [deliveryId]
  );
}

export async function markAlertDeliveryFailed(
  pool: pg.Pool,
  deliveryId: string,
  attemptsBeforeThisTry: number,
  error: string
) {
  const attempts = attemptsBeforeThisTry + 1;

  if (attempts >= MAX_ALERT_DELIVERY_ATTEMPTS) {
    await pool.query(
      `update alert_deliveries set status = 'failed', attempts = $2, last_error = $3 where id = $1`,
      [deliveryId, attempts, error]
    );
    return;
  }

  const backoffSeconds = Math.min(30 * 2 ** attempts, 3600);
  await pool.query(
    `
    update alert_deliveries
    set status = 'queued', attempts = $2, last_error = $3, next_attempt_at = now() + make_interval(secs => $4)
    where id = $1
    `,
    [deliveryId, attempts, error, backoffSeconds]
  );
}

function mergeIps(existing: unknown, ip?: string) {
  const values = Array.isArray(existing) ? existing.filter((value) => typeof value === "string") : [];
  if (ip && !values.includes(ip)) values.push(ip);
  return values;
}

function toJsonb(value: unknown) {
  return JSON.stringify(value);
}

function shouldQueueAlertDelivery(severity: string) {
  return severity === "high" || severity === "critical";
}
