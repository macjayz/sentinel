import pg from "pg";
import { ApiConfig } from "./config.js";

const { Pool } = pg;

export function createPool(config: ApiConfig) {
  return new Pool({ connectionString: config.databaseUrl });
}

export async function getOverview(pool: pg.Pool) {
  const [events, incidents, endpoints, ips] = await Promise.all([
    pool.query("select count(*)::int as total, avg(latency_ms)::float as latency from api_events"),
    pool.query("select count(*)::int as total from incidents where status = 'open'"),
    pool.query(`
      select path, method, count(*)::int as requests, avg(latency_ms)::float as latency,
             max(threat_score)::int as max_threat_score
      from api_events
      group by path, method
      order by requests desc
      limit 12
    `),
    pool.query(`
      select ip, count(*)::int as requests, max(threat_score)::int as max_threat_score
      from api_events
      where ip is not null
      group by ip
      order by requests desc
      limit 12
    `)
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

export async function getIncidents(pool: pg.Pool) {
  const result = await pool.query(`
    select id, event_id, severity, title, description, signals, status, created_at
    from incidents
    order by created_at desc
    limit 50
  `);

  return result.rows;
}

export type RequestFilters = {
  method?: string;
  status?: number;
  threatMin?: number;
  ip?: string;
  query?: string;
  limit?: number;
};

export async function getRequests(pool: pg.Pool, filters: RequestFilters = {}) {
  const clauses: string[] = [];
  const values: Array<string | number> = [];

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
    select id, timestamp, service_name, environment, kind, method, path, route, ip, user_agent,
           status_code, latency_ms, body_bytes, auth_present, auth_failed,
           graphql_operation_name, graphql_operation_type, evm_rpc_method,
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
