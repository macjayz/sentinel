import pg from "pg";
import { createHash, randomBytes } from "node:crypto";
import { generateSessionToken, hashPassword, hashToken, SESSION_TTL_MS } from "./auth.js";
import { ApiConfig } from "./config.js";

const { Pool } = pg;

export function createPool(config: ApiConfig) {
  return new Pool({ connectionString: config.databaseUrl });
}

export async function ensureBootstrapUser(
  pool: pg.Pool,
  projectId: string,
  email: string,
  password: string
) {
  const project = await pool.query(`select organization_id from projects where id = $1`, [projectId]);
  const organizationId = project.rows[0]?.organization_id;
  if (!organizationId) return;

  const normalizedEmail = normalizeEmail(email);
  const existing = await pool.query(`select id from users where lower(email) = $1`, [normalizedEmail]);
  if (existing.rows[0]) return;

  const passwordHash = await hashPassword(password);
  const created = await pool.query(
    `insert into users (organization_id, email, password_hash) values ($1, $2, $3) returning id`,
    [organizationId, normalizedEmail, passwordHash]
  );
  const userId = created.rows[0].id as string;

  await pool.query(
    `
    insert into project_memberships (project_id, user_id, role)
    values ($1, $2, 'owner')
    on conflict (project_id, user_id) do nothing
    `,
    [projectId, userId]
  );
}

export async function getUserByEmail(pool: pg.Pool, email: string) {
  const result = await pool.query(
    `
    select users.id, users.email, users.password_hash, users.organization_id,
           organizations.name as organization_name
    from users
    join organizations on organizations.id = users.organization_id
    where lower(users.email) = $1
    `,
    [normalizeEmail(email)]
  );

  return result.rows[0] ?? null;
}

export async function createWorkspaceOwner(
  pool: pg.Pool,
  input: {
    email: string;
    password: string;
    organizationName: string;
    projectName: string;
  }
) {
  const client = await pool.connect();
  const email = normalizeEmail(input.email);
  const projectId = makeProjectId(input.projectName);
  const passwordHash = await hashPassword(input.password);
  const key = `sentinel_${randomBytes(24).toString("base64url")}`;
  const prefix = key.slice(0, 17);

  try {
    await client.query("begin");

    const existing = await client.query(`select id from users where lower(email) = $1`, [email]);
    if (existing.rows[0]) {
      await client.query("rollback");
      return { kind: "email_exists" as const };
    }

    const organization = await client.query(
      `insert into organizations (name) values ($1) returning id, name`,
      [input.organizationName.trim()]
    );
    const organizationRow = organization.rows[0];

    const user = await client.query(
      `insert into users (organization_id, email, password_hash) values ($1, $2, $3) returning id, email`,
      [organizationRow.id, email, passwordHash]
    );
    const userRow = user.rows[0];

    const project = await client.query(
      `insert into projects (id, organization_id, name) values ($1, $2, $3) returning id, name`,
      [projectId, organizationRow.id, input.projectName.trim()]
    );
    const projectRow = project.rows[0];

    await client.query(`insert into project_memberships (project_id, user_id, role) values ($1, $2, 'owner')`, [
      projectRow.id,
      userRow.id
    ]);

    const apiKey = await client.query(
      `
      insert into api_keys (project_id, name, key_hash, prefix)
      values ($1, 'Default SDK key', $2, $3)
      returning id, name, prefix, last_used_at, created_at, revoked_at
      `,
      [projectRow.id, hashApiKey(key), prefix]
    );

    await client.query("commit");

    return {
      kind: "created" as const,
      user: { id: userRow.id as string, email: userRow.email as string },
      organization: { id: organizationRow.id as string, name: organizationRow.name as string },
      project: { id: projectRow.id as string, name: projectRow.name as string, role: "owner" as const },
      apiKey: { ...apiKey.rows[0], key }
    };
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export async function createSession(pool: pg.Pool, userId: string) {
  const token = generateSessionToken();
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();

  await pool.query(`insert into sessions (user_id, token_hash, expires_at) values ($1, $2, $3)`, [
    userId,
    hashToken(token),
    expiresAt
  ]);

  return { token, expiresAt };
}

export async function resolveSession(pool: pg.Pool, token: string | undefined) {
  if (!token) return null;

  const result = await pool.query(
    `
    select sessions.user_id, sessions.expires_at, users.email, users.organization_id,
           organizations.name as organization_name
    from sessions
    join users on users.id = sessions.user_id
    join organizations on organizations.id = users.organization_id
    where sessions.token_hash = $1
    `,
    [hashToken(token)]
  );

  const row = result.rows[0];
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now()) return null;

  return {
    userId: row.user_id as string,
    email: row.email as string,
    organizationId: row.organization_id as string,
    organizationName: row.organization_name as string
  };
}

export async function deleteSession(pool: pg.Pool, token: string) {
  await pool.query(`delete from sessions where token_hash = $1`, [hashToken(token)]);
}

export async function listMembershipsForUser(pool: pg.Pool, userId: string) {
  const result = await pool.query(
    `
    select project_memberships.project_id, project_memberships.role, projects.name
    from project_memberships
    join projects on projects.id = project_memberships.project_id
    where project_memberships.user_id = $1
    order by projects.name
    `,
    [userId]
  );

  return result.rows;
}

export async function getProjectRole(pool: pg.Pool, userId: string, projectId: string) {
  const result = await pool.query(
    `select role from project_memberships where user_id = $1 and project_id = $2`,
    [userId, projectId]
  );

  return (result.rows[0]?.role as string | undefined) ?? null;
}

export async function getOverview(pool: pg.Pool, projectId = "demo") {
  const [events, incidents, endpoints, ips] = await Promise.all([
    pool.query(
      "select count(*)::int as total, avg(latency_ms)::float as latency from api_events where project_id = $1",
      [projectId]
    ),
    pool.query("select count(*)::int as total from incidents where status in ('open', 'acknowledged') and project_id = $1", [
      projectId
    ]),
    pool.query(
      `
      select coalesce(route, path) as path, method, count(*)::int as requests, avg(latency_ms)::float as latency,
             max(threat_score)::int as max_threat_score
      from api_events
      where project_id = $1
      group by coalesce(route, path), method
      order by requests desc
      limit 12
    `,
      [projectId]
    ),
    pool.query(
      `
      select ip, count(*)::int as requests, max(threat_score)::int as max_threat_score
      from api_events
      where project_id = $1 and ip is not null
      group by ip
      order by requests desc
      limit 12
    `,
      [projectId]
    )
  ]);

  return {
    totals: {
      events: events.rows[0]?.total ?? 0,
      openIncidents: incidents.rows[0]?.total ?? 0,
      averageLatencyMs: Math.round(events.rows[0]?.latency ?? 0)
    },
    endpoints: endpoints.rows,
    ips: ips.rows
  };
}

export async function getIncidents(pool: pg.Pool, projectId = "demo") {
  const result = await pool.query(
    `
    select id, event_id, incident_key, severity, title, description, signals, status,
           affected_endpoint, attacker_ips, request_count, started_at, last_seen_at,
           acknowledged_at, resolved_at, ignored_at, updated_at, created_at
    from incidents
    where project_id = $1
    order by last_seen_at desc, created_at desc
    limit 50
  `,
    [projectId]
  );

  return result.rows;
}

export type IncidentStatus = "open" | "acknowledged" | "resolved" | "ignored";

export async function updateIncidentStatus(
  pool: pg.Pool,
  projectId: string,
  incidentId: string,
  status: IncidentStatus,
  actor = "demo-operator",
  note?: string
) {
  const timestampColumn = {
    open: null,
    acknowledged: "acknowledged_at",
    resolved: "resolved_at",
    ignored: "ignored_at"
  }[status];
  const assignments = ["status = $3", "updated_at = now()"];
  if (timestampColumn) assignments.push(`${timestampColumn} = now()`);

  const client = await pool.connect();
  try {
    await client.query("begin");
    const result = await client.query(
      `
      update incidents
      set ${assignments.join(", ")}
      where id = $1 and project_id = $2
      returning id, event_id, incident_key, severity, title, description, signals, status,
                affected_endpoint, attacker_ips, request_count, started_at, last_seen_at,
                acknowledged_at, resolved_at, ignored_at, updated_at, created_at
      `,
      [incidentId, projectId, status]
    );

    const incident = result.rows[0];
    if (!incident) {
      await client.query("rollback");
      return null;
    }

    await client.query(
      `
      insert into incident_timeline (incident_id, project_id, action, actor, note)
      values ($1, $2, $3, $4, $5)
      `,
      [incidentId, projectId, `status:${status}`, actor, note ?? null]
    );

    await client.query("commit");
    return incident;
  } catch (error) {
    await client.query("rollback");
    throw error;
  } finally {
    client.release();
  }
}

export async function getIncidentTimeline(pool: pg.Pool, projectId: string, incidentId: string) {
  const result = await pool.query(
    `
    select id, incident_id, action, actor, note, created_at
    from incident_timeline
    where project_id = $1 and incident_id = $2
    order by created_at desc
    limit 50
    `,
    [projectId, incidentId]
  );

  return result.rows;
}

export async function listAlertDestinations(pool: pg.Pool, projectId: string) {
  const result = await pool.query(
    `
    select id, name, url, enabled, created_at, updated_at
    from alert_destinations
    where project_id = $1
    order by created_at desc
    `,
    [projectId]
  );

  return result.rows;
}

export async function createAlertDestination(pool: pg.Pool, projectId: string, name: string, url: string) {
  const result = await pool.query(
    `
    insert into alert_destinations (project_id, name, url)
    values ($1, $2, $3)
    returning id, name, url, enabled, created_at, updated_at
    `,
    [projectId, name, url]
  );

  return result.rows[0];
}

export async function updateAlertDestination(
  pool: pg.Pool,
  projectId: string,
  destinationId: string,
  enabled: boolean
) {
  const result = await pool.query(
    `
    update alert_destinations
    set enabled = $3, updated_at = now()
    where id = $1 and project_id = $2
    returning id, name, url, enabled, created_at, updated_at
    `,
    [destinationId, projectId, enabled]
  );

  return result.rows[0] ?? null;
}

export const AlertRuleMetrics = [
  "error_rate_percent",
  "p95_latency_ms",
  "max_threat_score",
  "request_count",
  "auth_failure_count"
] as const;

export type AlertRuleMetric = (typeof AlertRuleMetrics)[number];

export async function listAlertRules(pool: pg.Pool, projectId: string) {
  const result = await pool.query(
    `
    select id, metric, threshold, window_minutes, enabled, created_at, updated_at
    from alert_rules
    where project_id = $1
    order by created_at desc
    `,
    [projectId]
  );

  return result.rows;
}

export async function createAlertRule(
  pool: pg.Pool,
  projectId: string,
  metric: AlertRuleMetric,
  threshold: number,
  windowMinutes: number
) {
  const result = await pool.query(
    `
    insert into alert_rules (project_id, metric, threshold, window_minutes)
    values ($1, $2, $3, $4)
    returning id, metric, threshold, window_minutes, enabled, created_at, updated_at
    `,
    [projectId, metric, threshold, windowMinutes]
  );

  return result.rows[0];
}

export async function updateAlertRule(
  pool: pg.Pool,
  projectId: string,
  ruleId: string,
  updates: { enabled?: boolean; threshold?: number; windowMinutes?: number }
) {
  const result = await pool.query(
    `
    update alert_rules
    set
      enabled = coalesce($3, enabled),
      threshold = coalesce($4, threshold),
      window_minutes = coalesce($5, window_minutes),
      updated_at = now()
    where id = $1 and project_id = $2
    returning id, metric, threshold, window_minutes, enabled, created_at, updated_at
    `,
    [ruleId, projectId, updates.enabled ?? null, updates.threshold ?? null, updates.windowMinutes ?? null]
  );

  return result.rows[0] ?? null;
}

export async function listAlertDeliveries(pool: pg.Pool, projectId: string) {
  const result = await pool.query(
    `
    select deliveries.id, deliveries.incident_id, deliveries.destination_id, destinations.name as destination_name,
           deliveries.status, deliveries.attempts, deliveries.last_error, deliveries.created_at, deliveries.delivered_at
    from alert_deliveries deliveries
    join alert_destinations destinations on destinations.id = deliveries.destination_id
    where deliveries.project_id = $1
    order by deliveries.created_at desc
    limit 50
    `,
    [projectId]
  );

  return result.rows;
}

export async function listErrorGroups(pool: pg.Pool, projectId: string) {
  const result = await pool.query(
    `
    select id, error_type, message, affected_endpoint, occurrences, affected_ips,
           first_seen_at, last_seen_at
    from error_groups
    where project_id = $1
    order by last_seen_at desc
    limit 100
    `,
    [projectId]
  );

  return result.rows;
}

export type RequestFilters = {
  projectId?: string;
  kind?: string;
  method?: string;
  status?: number;
  threatMin?: number;
  ip?: string;
  query?: string;
  limit?: number;
};

export async function getRequests(pool: pg.Pool, filters: RequestFilters = {}) {
  const clauses: string[] = ["project_id = $1"];
  const values: Array<string | number> = [filters.projectId ?? "demo"];

  if (filters.kind) {
    values.push(filters.kind);
    clauses.push(`kind = $${values.length}`);
  }

  if (filters.method) {
    values.push(filters.method.toUpperCase());
    clauses.push(`method = $${values.length}`);
  }

  if (filters.status) {
    values.push(filters.status);
    clauses.push(`status_code = $${values.length}`);
  }

  if (filters.threatMin) {
    values.push(filters.threatMin);
    clauses.push(`threat_score >= $${values.length}`);
  }

  if (filters.ip) {
    values.push(filters.ip);
    clauses.push(`ip = $${values.length}`);
  }

  if (filters.query) {
    values.push(`%${filters.query}%`);
    clauses.push(`(path ilike $${values.length} or route ilike $${values.length})`);
  }

  values.push(Math.min(Math.max(filters.limit ?? 50, 1), 100));
  const limitPlaceholder = `$${values.length}`;
  const where = clauses.length > 0 ? `where ${clauses.join(" and ")}` : "";

  const result = await pool.query(
    `
    select id, trace_id, parent_span_id, timestamp, service_name, environment, kind, method, path, route, ip, user_agent,
           status_code, latency_ms, body_bytes, auth_present, auth_failed,
           graphql_operation_name, graphql_operation_type, evm_rpc_method,
           evm_chain_id, evm_provider, wallet_address, contract_address,
           threat_score, threat_severity
    from api_events
    ${where}
    order by timestamp desc
    limit ${limitPlaceholder}
    `,
    values
  );

  return result.rows;
}

export async function resolveProjectForApiKey(
  pool: pg.Pool,
  apiKey: string,
  fallbackApiKey: string,
  requestedProjectId?: string,
  allowFallbackApiKey = false
) {
  if (allowFallbackApiKey && apiKey === fallbackApiKey) {
    return { projectId: requestedProjectId ?? "demo", keyId: "env-fallback" };
  }

  const result = await pool.query(
    `
    update api_keys
    set last_used_at = now()
    where key_hash = $1 and revoked_at is null
    returning id, project_id
    `,
    [hashApiKey(apiKey)]
  );

  const row = result.rows[0];
  if (!row) return null;
  return { projectId: row.project_id as string, keyId: row.id as string };
}

export function hashApiKey(apiKey: string) {
  return createHash("sha256").update(apiKey).digest("hex");
}

function normalizeEmail(email: string) {
  return email.trim().toLowerCase();
}

function makeProjectId(name: string) {
  const slug = name
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 36);

  return `${slug || "project"}-${randomBytes(4).toString("hex")}`;
}

export async function listApiKeys(pool: pg.Pool, projectId: string) {
  const result = await pool.query(
    `
    select id, name, prefix, last_used_at, created_at, revoked_at
    from api_keys
    where project_id = $1
    order by created_at desc
    `,
    [projectId]
  );

  return result.rows;
}

export async function createApiKey(pool: pg.Pool, projectId: string, name: string) {
  const key = `sentinel_${randomBytes(24).toString("base64url")}`;
  const prefix = key.slice(0, 17);
  const result = await pool.query(
    `
    insert into api_keys (project_id, name, key_hash, prefix)
    values ($1, $2, $3, $4)
    returning id, name, prefix, last_used_at, created_at, revoked_at
    `,
    [projectId, name, hashApiKey(key), prefix]
  );

  return {
    ...result.rows[0],
    key
  };
}

export async function revokeApiKey(pool: pg.Pool, projectId: string, keyId: string) {
  const result = await pool.query(
    `
    update api_keys
    set revoked_at = now()
    where id = $1 and project_id = $2 and revoked_at is null
    returning id
    `,
    [keyId, projectId]
  );

  return (result.rowCount ?? 0) > 0;
}
