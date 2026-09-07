import pg from "pg";
import {
  redactHeaders,
  redactValue,
  SentinelEvent,
  ThreatAssessment,
  Web3ThreatContext,
  withSpan
} from "@sentinel/shared";
import { AlertRule } from "./alertRules.js";
import { WorkerConfig } from "./config.js";
import { fingerprintError } from "./errors.js";
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

export async function countRecentEvmMethodCalls(
  pool: pg.Pool,
  projectId: string,
  method: string,
  ip: string | undefined
) {
  if (!ip) return 0;
  const result = await pool.query(
    `
    select count(*)::int as count
    from api_events
    where project_id = $1 and kind = 'evm_rpc' and evm_rpc_method = $2 and ip = $3
      and timestamp > now() - interval '1 minute'
    `,
    [projectId, method, ip]
  );

  return result.rows[0]?.count ?? 0;
}

export async function getWalletTransactionStats(
  pool: pg.Pool,
  projectId: string,
  walletAddress: string | undefined
) {
  if (!walletAddress) return { recentHourCount: 0, baselineHourlyAverage: 0 };

  const result = await pool.query(
    `
    select
      count(*) filter (where timestamp > now() - interval '1 hour')::int as recent_hour_count,
      (
        count(*) filter (
          where timestamp > now() - interval '25 hours' and timestamp <= now() - interval '1 hour'
        )::float / 24
      ) as baseline_hourly_average
    from api_events
    where project_id = $1 and kind = 'evm_rpc' and wallet_address = $2
      and evm_rpc_method ~* 'sendrawtransaction|sendtransaction'
    `,
    [projectId, walletAddress]
  );

  const row = result.rows[0];
  return {
    recentHourCount: row?.recent_hour_count ?? 0,
    baselineHourlyAverage: Number(row?.baseline_hourly_average ?? 0)
  };
}

export async function getProviderRpcStats(pool: pg.Pool, projectId: string, provider: string | undefined) {
  if (!provider) return { recentP95LatencyMs: 0, baselineP95LatencyMs: 0, recentFailureRate: 0 };

  const result = await pool.query(
    `
    select
      percentile_cont(0.95) within group (order by latency_ms)
        filter (where timestamp > now() - interval '5 minutes') as recent_p95,
      percentile_cont(0.95) within group (order by latency_ms)
        filter (where timestamp > now() - interval '24 hours' and timestamp <= now() - interval '5 minutes') as baseline_p95,
      count(*) filter (where timestamp > now() - interval '5 minutes')::int as recent_total,
      count(*) filter (
        where timestamp > now() - interval '5 minutes' and status_code >= 400
      )::int as recent_failures
    from api_events
    where project_id = $1 and kind = 'evm_rpc' and evm_provider = $2
    `,
    [projectId, provider]
  );

  const row = result.rows[0];
  const recentTotal = row?.recent_total ?? 0;
  return {
    recentP95LatencyMs: Number(row?.recent_p95 ?? 0),
    baselineP95LatencyMs: Number(row?.baseline_p95 ?? 0),
    // Require a minimum sample size so a single failed call out of one or two requests
    // doesn't read as a 100% failure rate.
    recentFailureRate: recentTotal >= 5 ? (row?.recent_failures ?? 0) / recentTotal : 0
  };
}

export async function getWeb3ThreatContext(pool: pg.Pool, event: SentinelEvent): Promise<Web3ThreatContext> {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return {};

  const [methodCallCount, walletStats, providerStats] = await Promise.all([
    countRecentEvmMethodCalls(pool, event.projectId, event.evmRpc.method, event.request.ip),
    getWalletTransactionStats(pool, event.projectId, event.evmRpc.walletAddress),
    getProviderRpcStats(pool, event.projectId, event.evmRpc.provider)
  ]);

  return {
    recentMethodCallCount: methodCallCount,
    walletRecentHourTxCount: walletStats.recentHourCount,
    walletBaselineHourlyTxCount: walletStats.baselineHourlyAverage,
    providerRecentP95LatencyMs: providerStats.recentP95LatencyMs,
    providerBaselineP95LatencyMs: providerStats.baselineP95LatencyMs,
    providerRecentFailureRate: providerStats.recentFailureRate
  };
}

export async function persistEvent(pool: pg.Pool, event: SentinelEvent, assessment: ThreatAssessment) {
  const requestHeaders = redactHeaders(event.request.headers);
  const requestBody = redactValue(event.request.body ?? null);

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
      error_type, error_message, error_stack,
      threat_score, threat_severity, threat_signals
    )
    values (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
      $13, $14, $15, $16, $17, $18,
      $19, $20, $21, $22, $23,
      $24, $25, $26, $27, $28,
      $29, $30, $31,
      $32, $33, $34
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
          toJsonb(requestHeaders),
          toJsonb(event.request.query),
          toJsonb(requestBody),
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
          event.error?.type,
          event.error?.message,
          event.error?.stack,
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

export async function raiseAlertRuleIncident(pool: pg.Pool, rule: AlertRule, value: number) {
  const incidentKey = `${rule.project_id}:alert_rule:${rule.metric}`;
  const label = describeAlertRuleMetric(rule.metric);
  const title = `${label} exceeded threshold`;
  const description = `${label} reached ${formatAlertRuleValue(rule.metric, value)}, above the configured threshold of ${formatAlertRuleValue(
    rule.metric,
    rule.threshold
  )}.`;
  const now = new Date().toISOString();

  const client = await pool.connect();
  try {
    await client.query("begin");

    const existing = await client.query(
      `select id from incidents where incident_key = $1 and status in ('open', 'acknowledged') for update`,
      [incidentKey]
    );

    let incidentId: string | null = null;
    let isNewIncident = false;

    if (existing.rows[0]) {
      incidentId = existing.rows[0].id;
      await client.query(
        `
        update incidents
        set description = $2, last_seen_at = $3, request_count = request_count + 1
        where id = $1
        `,
        [incidentId, description, now]
      );
    } else {
      const created = await client.query(
        `
        insert into incidents (
          event_id, incident_key, project_id, severity, title, description, signals,
          affected_endpoint, attacker_ips, request_count, started_at, last_seen_at, status
        )
        values (null, $1, $2, 'high', $3, $4, $5, $6, $7, 1, $8, $8, 'open')
        on conflict (incident_key) do nothing
        returning id
        `,
        [
          incidentKey,
          rule.project_id,
          title,
          description,
          toJsonb([]),
          "All endpoints",
          toJsonb([]),
          now
        ]
      );
      incidentId = created.rows[0]?.id ?? null;
      isNewIncident = Boolean(incidentId);
    }

    if (incidentId && isNewIncident) {
      await client.query(
        `
        insert into alert_deliveries (incident_id, destination_id, project_id, status)
        select $1, id, project_id, 'queued'
        from alert_destinations
        where project_id = $2 and enabled = true
        `,
        [incidentId, rule.project_id]
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

function describeAlertRuleMetric(metric: string): string {
  switch (metric) {
    case "error_rate_percent":
      return "Error rate";
    case "p95_latency_ms":
      return "p95 latency";
    case "max_threat_score":
      return "Threat score";
    case "request_count":
      return "Request volume";
    case "auth_failure_count":
      return "Authentication failures";
    default:
      return metric;
  }
}

function formatAlertRuleValue(metric: string, value: number): string {
  switch (metric) {
    case "error_rate_percent":
      return `${value.toFixed(1)}%`;
    case "p95_latency_ms":
      return `${Math.round(value)}ms`;
    default:
      return `${Math.round(value)}`;
  }
}

export async function recordErrorGroup(pool: pg.Pool, event: SentinelEvent) {
  const fingerprint = fingerprintError(event);
  if (!fingerprint) return;

  const client = await pool.connect();
  try {
    await client.query("begin");

    const existing = await client.query(
      `select id, affected_ips from error_groups where project_id = $1 and fingerprint = $2 for update`,
      [event.projectId, fingerprint.key]
    );

    if (existing.rows[0]) {
      const affectedIps = mergeIps(existing.rows[0].affected_ips, event.request.ip);
      await client.query(
        `
        update error_groups
        set occurrences = occurrences + 1, last_seen_at = $2, affected_ips = $3, updated_at = now()
        where id = $1
        `,
        [existing.rows[0].id, event.timestamp, toJsonb(affectedIps)]
      );
    } else {
      await client.query(
        `
        insert into error_groups (
          project_id, fingerprint, error_type, message, affected_endpoint, occurrences, affected_ips,
          sample_stack, first_seen_at, last_seen_at
        )
        values ($1, $2, $3, $4, $5, 1, $6, $7, $8, $8)
        on conflict (project_id, fingerprint) do nothing
        `,
        [
          event.projectId,
          fingerprint.key,
          fingerprint.errorType,
          fingerprint.message,
          fingerprint.affectedEndpoint,
          toJsonb(mergeIps([], event.request.ip)),
          event.error?.stack ?? null,
          event.timestamp
        ]
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
