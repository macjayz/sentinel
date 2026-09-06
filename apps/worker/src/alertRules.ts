import pg from "pg";
import { withSpan } from "@sentinel/shared";

export type AlertRule = {
  id: string;
  project_id: string;
  metric: string;
  threshold: number;
  window_minutes: number;
};

export async function listEnabledAlertRules(pool: pg.Pool): Promise<AlertRule[]> {
  const result = await pool.query(
    `select id, project_id, metric, threshold::float as threshold, window_minutes from alert_rules where enabled = true`
  );

  return result.rows;
}

export async function evaluateAlertRuleMetric(pool: pg.Pool, rule: AlertRule): Promise<number | null> {
  switch (rule.metric) {
    case "error_rate_percent": {
      const result = await pool.query(
        `
        select
          case when count(*) = 0 then null
          else count(*) filter (where status_code >= 500)::float / count(*) * 100
          end as value
        from api_events
        where project_id = $1 and timestamp > now() - make_interval(mins => $2)
        `,
        [rule.project_id, rule.window_minutes]
      );
      return numericOrNull(result.rows[0]?.value);
    }
    case "p95_latency_ms": {
      const result = await pool.query(
        `
        select percentile_cont(0.95) within group (order by latency_ms) as value
        from api_events
        where project_id = $1 and timestamp > now() - make_interval(mins => $2)
        `,
        [rule.project_id, rule.window_minutes]
      );
      return numericOrNull(result.rows[0]?.value);
    }
    case "max_threat_score": {
      const result = await pool.query(
        `
        select max(threat_score) as value
        from api_events
        where project_id = $1 and timestamp > now() - make_interval(mins => $2)
        `,
        [rule.project_id, rule.window_minutes]
      );
      return numericOrNull(result.rows[0]?.value);
    }
    case "request_count": {
      const result = await pool.query(
        `
        select count(*)::int as value
        from api_events
        where project_id = $1 and timestamp > now() - make_interval(mins => $2)
        `,
        [rule.project_id, rule.window_minutes]
      );
      return Number(result.rows[0]?.value ?? 0);
    }
    case "auth_failure_count": {
      const result = await pool.query(
        `
        select count(*)::int as value
        from api_events
        where project_id = $1 and auth_failed = true and timestamp > now() - make_interval(mins => $2)
        `,
        [rule.project_id, rule.window_minutes]
      );
      return Number(result.rows[0]?.value ?? 0);
    }
    default:
      return null;
  }
}

export async function evaluateAlertRules(
  pool: pg.Pool,
  raiseIncident: (pool: pg.Pool, rule: AlertRule, value: number) => Promise<void>
) {
  const rules = await listEnabledAlertRules(pool);

  for (const rule of rules) {
    await withSpan(
      "sentinel.worker.evaluate_alert_rule",
      { "sentinel.alert_rule_id": rule.id, "sentinel.alert_rule_metric": rule.metric },
      async () => {
        const value = await evaluateAlertRuleMetric(pool, rule);
        if (value !== null && value > rule.threshold) {
          await raiseIncident(pool, rule, value);
        }
      }
    );
  }
}

function numericOrNull(value: unknown): number | null {
  return value === null || value === undefined ? null : Number(value);
}
