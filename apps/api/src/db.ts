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
