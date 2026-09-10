import pg from "pg";
import {
  redactHeaders,
  redactValue,
  SentinelEvent,
  ThreatAssessment,
  Web3ThreatContext,
  withSpan,
  type CostWasteContext,
  type DisagreementContext,
  type ReorgContext,
  type SilentFailureContext,
  type StaleHeadContext,
  type ThrottlingContext
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

/** The `params` array as the SDK recorded it, used to match a call against earlier identical ones. */
function rpcParams(event: SentinelEvent): unknown[] | undefined {
  const body = event.request.body;
  if (!body || typeof body !== "object") return undefined;
  const params = (body as { params?: unknown }).params;
  return Array.isArray(params) ? params : undefined;
}

/**
 * Head state for detector D1.
 *
 * Only `latest`-tagged observations count: a call pinned to a past block or asking for
 * finalized state says nothing about how current the provider's head is.
 */
export async function getStaleHeadContext(
  pool: pg.Pool,
  projectId: string,
  chainId: string | undefined,
  endpointHash: string | undefined
): Promise<StaleHeadContext> {
  if (!chainId) return {};

  const result = await pool.query(
    `
    with observations as (
      select timestamp, evm_block_number
      from api_events
      where project_id = $1 and kind = 'evm_rpc' and evm_chain_id = $2
        and evm_endpoint_hash is not distinct from $3
        and evm_block_number is not null
        and (evm_block_tag is null or evm_block_tag = 'latest')
        and timestamp > now() - interval '15 minutes'
    ),
    head as (
      select max(evm_block_number) as value from observations
    )
    select
      (select value from head)::bigint as endpoint_head,
      (select count(*) from observations)::int as observations,
      -- When the head first reached its current value. Anything after that is time the
      -- provider spent answering without moving forward.
      (select min(timestamp) from observations where evm_block_number = (select value from head)) as head_since,
      (select max(evm_block_number) - min(evm_block_number) from observations)::bigint as block_span,
      (select extract(epoch from (max(timestamp) - min(timestamp))) from observations) as span_seconds,
      (
        select max(evm_block_number)
        from api_events
        where project_id = $1 and kind = 'evm_rpc' and evm_chain_id = $2
          and evm_block_number is not null
          and (evm_block_tag is null or evm_block_tag = 'latest')
          and timestamp > now() - interval '5 minutes'
      )::bigint as chain_head
    `,
    [projectId, chainId, endpointHash ?? null]
  );

  const row = result.rows[0];
  if (!row) return {};

  const headSince = row.head_since ? new Date(row.head_since).getTime() : undefined;
  const blockSpan = row.block_span === null ? 0 : Number(row.block_span);
  const spanSeconds = Number(row.span_seconds ?? 0);

  return {
    endpointHeadBlockNumber: row.endpoint_head === null ? undefined : Number(row.endpoint_head),
    endpointHeadObservations: row.observations ?? 0,
    endpointHeadStalledMs: headSince === undefined ? undefined : Date.now() - headSince,
    chainHeadBlockNumber: row.chain_head === null ? undefined : Number(row.chain_head),
    // Mean interval across the window, used only for chains absent from the static table.
    measuredBlockTimeMs: blockSpan > 0 && spanSeconds > 0 ? (spanSeconds * 1000) / blockSpan : undefined
  };
}

/**
 * Comparative history for detector D3.
 *
 * Each lookup answers "did this same endpoint previously answer this same question
 * differently?", because an empty or null result on its own is usually correct.
 */
export async function getSilentFailureContext(
  pool: pg.Pool,
  projectId: string,
  event: SentinelEvent
): Promise<SilentFailureContext> {
  const evmRpc = event.evmRpc;
  if (!evmRpc) return {};

  const endpointHash = evmRpc.endpointHash ?? null;
  const params = rpcParams(event);
  const context: SilentFailureContext = {};

  if (evmRpc.resultShape === "null" && typeof params?.[0] === "string") {
    const result = await pool.query(
      `
      select exists (
        select 1 from api_events
        where project_id = $1 and kind = 'evm_rpc' and evm_rpc_method = $2
          and evm_endpoint_hash is not distinct from $3
          and request_body -> 'params' ->> 0 = $4
          and evm_result_shape is not null and evm_result_shape <> 'null'
          and timestamp > now() - interval '24 hours'
      ) as prior
      `,
      [projectId, evmRpc.method, endpointHash, params[0]]
    );
    context.priorNonNullForSameTarget = Boolean(result.rows[0]?.prior);
  }

  if (evmRpc.resultShape === "empty_data" && params?.[0] !== undefined) {
    // Compare only params[0] — the call itself. params[1] is the block tag, which is
    // expected to differ between the earlier successful call and this one.
    const result = await pool.query(
      `
      select exists (
        select 1 from api_events
        where project_id = $1 and kind = 'evm_rpc' and evm_rpc_method = $2
          and evm_endpoint_hash is not distinct from $3
          and request_body -> 'params' -> 0 = $4::jsonb
          and evm_result_shape = 'value'
          and (evm_block_number is null or $5::bigint is null or evm_block_number < $5::bigint)
          and timestamp > now() - interval '24 hours'
      ) as prior
      `,
      [projectId, evmRpc.method, endpointHash, JSON.stringify(params[0]), evmRpc.blockNumber ?? null]
    );
    context.priorDataForSameCall = Boolean(result.rows[0]?.prior);
  }

  if (evmRpc.resultCount !== undefined) {
    const result = await pool.query(
      `
      select evm_result_count as max_count, count(*)::int as hits
      from api_events
      where project_id = $1 and kind = 'evm_rpc' and evm_rpc_method = $2
        and evm_endpoint_hash is not distinct from $3
        and evm_result_count is not null
        and timestamp > now() - interval '24 hours'
      group by evm_result_count
      order by evm_result_count desc
      limit 1
      `,
      [projectId, evmRpc.method, endpointHash]
    );
    const row = result.rows[0];
    if (row) {
      context.endpointMaxResultCount = Number(row.max_count);
      context.endpointMaxResultCountHits = row.hits ?? 0;
    }
  }

  return context;
}

/**
 * Duplicate-call accounting for detector D6.
 *
 * Scoped strictly to one block height: two identical calls either side of a block
 * boundary are legitimate polling, not waste.
 */
export async function getCostWasteContext(
  pool: pg.Pool,
  projectId: string,
  event: SentinelEvent
): Promise<CostWasteContext> {
  const evmRpc = event.evmRpc;
  if (!evmRpc?.blockNumber) return {};

  const params = rpcParams(event);
  if (!params) return {};

  const result = await pool.query(
    `
    select count(*)::int as duplicates, coalesce(sum(evm_cost_units), 0)::int as cost_units
    from api_events
    where project_id = $1 and kind = 'evm_rpc' and evm_rpc_method = $2
      and evm_block_number = $3::bigint
      and request_body -> 'params' = $4::jsonb
      and timestamp > now() - interval '1 hour'
    `,
    [projectId, evmRpc.method, evmRpc.blockNumber, JSON.stringify(params)]
  );

  const row = result.rows[0];
  return {
    duplicateCallCount: row?.duplicates ?? 0,
    duplicateCostUnits: row?.cost_units ?? 0
  };
}

/**
 * Sibling verification results for detector D2.
 *
 * Only populated for shadow events — observations produced by asking several endpoints the
 * same block-pinned question. Siblings that could not answer (a null, or a JSON-RPC error)
 * are counted as missing the block rather than compared: an endpoint that lacks the block
 * has a stale head, which is D1's finding, not a disagreement.
 */
export async function getDisagreementContext(
  pool: pg.Pool,
  projectId: string,
  event: SentinelEvent
): Promise<DisagreementContext> {
  const evmRpc = event.evmRpc;
  if (!evmRpc?.shadowOfTraceId || !evmRpc.blockNumber || !evmRpc.resultHash) return {};

  const result = await pool.query(
    `
    select evm_endpoint_hash, evm_provider, evm_result_hash, evm_result_shape
    from api_events
    where project_id = $1
      and evm_shadow_of_trace_id = $2
      and evm_block_number = $3::bigint
      and id <> $4
    `,
    [projectId, evmRpc.shadowOfTraceId, evmRpc.blockNumber, event.id]
  );

  const peerResults: NonNullable<DisagreementContext["peerResults"]> = [];
  let peersMissingBlock = 0;

  for (const row of result.rows) {
    const comparable = row.evm_result_hash && row.evm_result_shape === "value";
    if (!comparable) {
      peersMissingBlock += 1;
      continue;
    }

    peerResults.push({
      endpointHash: row.evm_endpoint_hash ?? undefined,
      provider: row.evm_provider ?? undefined,
      resultHash: row.evm_result_hash
    });
  }

  return { peerResults, peersMissingBlock };
}

/**
 * Chain view for detector D4.
 *
 * A hash seen at a height *before* this one arrived means the chain was rewritten under
 * us. A different hash seen *after* ours, from another endpoint, means the peers have
 * moved on and this endpoint is still serving a block they abandoned.
 */
export async function getReorgContext(
  pool: pg.Pool,
  projectId: string,
  event: SentinelEvent
): Promise<ReorgContext> {
  const evmRpc = event.evmRpc;
  if (!evmRpc?.blockHash || !evmRpc.blockNumber || !evmRpc.chainId) return {};

  const result = await pool.query(
    `
    with at_height as (
      select evm_block_hash, evm_endpoint_hash, min(timestamp) as first_seen
      from api_events
      where project_id = $1 and evm_chain_id = $2 and evm_block_number = $3::bigint
        and evm_block_hash is not null
        and timestamp > now() - interval '1 hour'
      group by evm_block_hash, evm_endpoint_hash
    ),
    ours as (
      select min(first_seen) as first_seen from at_height where evm_block_hash = $4
    )
    select
      (
        select evm_block_hash from at_height
        where evm_block_hash <> $4
          and ((select first_seen from ours) is null or first_seen < (select first_seen from ours))
        order by first_seen desc limit 1
      ) as prior_hash,
      (
        select min(first_seen) from at_height
        where evm_block_hash <> $4
          and evm_endpoint_hash is distinct from $5
          and ((select first_seen from ours) is null or first_seen > (select first_seen from ours))
      ) as peer_moved_on_at,
      (
        select count(*)::int from (
          select evm_block_number
          from api_events
          where project_id = $1 and evm_chain_id = $2
            and evm_block_number between $3::bigint - 32 and $3::bigint
            and evm_block_hash is not null
            and timestamp > now() - interval '1 hour'
          group by evm_block_number
          having count(distinct evm_block_hash) > 1
        ) rewritten
      ) as reorg_depth
    `,
    [projectId, evmRpc.chainId, evmRpc.blockNumber, evmRpc.blockHash, evmRpc.endpointHash ?? null]
  );

  const row = result.rows[0];
  if (!row) return {};

  const peerMovedOnAt = row.peer_moved_on_at ? new Date(row.peer_moved_on_at).getTime() : undefined;

  return {
    priorBlockHashAtHeight: row.prior_hash ?? undefined,
    reorgDepth: row.reorg_depth ?? 0,
    supersededByPeer: peerMovedOnAt !== undefined,
    peerConvergenceLagMs: peerMovedOnAt === undefined ? undefined : Date.now() - peerMovedOnAt
  };
}

/**
 * Throttle and result-quality rates for detector D5.
 *
 * Degradation rates are computed only over events that actually carry a result shape, so
 * traffic recorded before result capture existed cannot dilute the ratio and hide a real
 * decline in answer quality.
 */
export async function getThrottlingContext(
  pool: pg.Pool,
  projectId: string,
  endpointHash: string | undefined
): Promise<ThrottlingContext> {
  const result = await pool.query(
    `
    select
      count(*) filter (where timestamp > now() - interval '5 minutes')::int as recent_total,
      count(*) filter (
        where timestamp > now() - interval '5 minutes' and evm_throttled
      )::int as recent_throttled,
      count(*) filter (
        where timestamp > now() - interval '5 minutes' and evm_result_shape is not null
      )::int as recent_shaped,
      count(*) filter (
        where timestamp > now() - interval '5 minutes'
          and evm_result_shape is not null and evm_result_shape <> 'value'
      )::int as recent_degraded,
      count(*) filter (
        where timestamp between now() - interval '24 hours' and now() - interval '5 minutes'
          and evm_result_shape is not null
      )::int as baseline_shaped,
      count(*) filter (
        where timestamp between now() - interval '24 hours' and now() - interval '5 minutes'
          and evm_result_shape is not null and evm_result_shape <> 'value'
      )::int as baseline_degraded
    from api_events
    where project_id = $1 and kind = 'evm_rpc'
      and evm_endpoint_hash is not distinct from $2
    `,
    [projectId, endpointHash ?? null]
  );

  const row = result.rows[0];
  if (!row) return {};

  const recentTotal = row.recent_total ?? 0;
  const recentShaped = row.recent_shaped ?? 0;
  const baselineShaped = row.baseline_shaped ?? 0;

  return {
    recentRequestCount: recentTotal,
    recentThrottleRate: recentTotal > 0 ? (row.recent_throttled ?? 0) / recentTotal : 0,
    recentDegradedResultRate: recentShaped > 0 ? (row.recent_degraded ?? 0) / recentShaped : 0,
    baselineDegradedResultRate: baselineShaped > 0 ? (row.baseline_degraded ?? 0) / baselineShaped : 0
  };
}

export async function getWeb3ThreatContext(pool: pg.Pool, event: SentinelEvent): Promise<Web3ThreatContext> {
  if (event.kind !== "evm_rpc" || !event.evmRpc) return {};

  const [
    methodCallCount,
    walletStats,
    providerStats,
    staleHead,
    silentFailure,
    costWaste,
    disagreement,
    reorg,
    throttling
  ] = await Promise.all([
    countRecentEvmMethodCalls(pool, event.projectId, event.evmRpc.method, event.request.ip),
    getWalletTransactionStats(pool, event.projectId, event.evmRpc.walletAddress),
    getProviderRpcStats(pool, event.projectId, event.evmRpc.provider),
    getStaleHeadContext(pool, event.projectId, event.evmRpc.chainId, event.evmRpc.endpointHash),
    getSilentFailureContext(pool, event.projectId, event),
    getCostWasteContext(pool, event.projectId, event),
    getDisagreementContext(pool, event.projectId, event),
    getReorgContext(pool, event.projectId, event),
    getThrottlingContext(pool, event.projectId, event.evmRpc.endpointHash)
  ]);

  return {
    recentMethodCallCount: methodCallCount,
    walletRecentHourTxCount: walletStats.recentHourCount,
    walletBaselineHourlyTxCount: walletStats.baselineHourlyAverage,
    providerRecentP95LatencyMs: providerStats.recentP95LatencyMs,
    providerBaselineP95LatencyMs: providerStats.baselineP95LatencyMs,
    providerRecentFailureRate: providerStats.recentFailureRate,
    staleHead,
    silentFailure,
    costWaste,
    disagreement,
    reorg,
    // Latency comes from the provider stats already gathered above rather than a second
    // query: D5's soft rule needs the same p95 figures provider_degradation uses.
    throttling: {
      ...throttling,
      recentP95LatencyMs: providerStats.recentP95LatencyMs,
      baselineP95LatencyMs: providerStats.baselineP95LatencyMs
    }
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
      evm_block_tag, evm_block_number, evm_block_hash, evm_result_hash, evm_result_shape,
      evm_rpc_error_code, evm_rpc_error_message, evm_endpoint_hash, evm_cost_units,
      evm_shadow_of_trace_id, evm_result_count, evm_throttled,
      error_type, error_message, error_stack,
      threat_score, threat_severity, threat_signals
    )
    values (
      $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
      $13, $14, $15, $16, $17, $18,
      $19, $20, $21, $22, $23,
      $24, $25, $26, $27, $28,
      $29, $30, $31, $32, $33,
      $34, $35, $36, $37,
      $38, $39, $40,
      $41, $42, $43,
      $44, $45, $46
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
          event.evmRpc?.blockTag,
          event.evmRpc?.blockNumber,
          event.evmRpc?.blockHash,
          event.evmRpc?.resultHash,
          event.evmRpc?.resultShape,
          event.evmRpc?.rpcErrorCode,
          event.evmRpc?.rpcErrorMessage,
          event.evmRpc?.endpointHash,
          event.evmRpc?.costUnits,
          event.evmRpc?.shadowOfTraceId,
          event.evmRpc?.resultCount,
          event.evmRpc?.throttled,
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
