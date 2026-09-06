import { describe, expect, it, vi } from "vitest";
import { evaluateAlertRuleMetric, evaluateAlertRules, type AlertRule } from "./alertRules.js";

const rule: AlertRule = {
  id: "rule-1",
  project_id: "demo",
  metric: "error_rate_percent",
  threshold: 5,
  window_minutes: 5
};

describe("evaluateAlertRuleMetric", () => {
  it("computes the error rate percentage over the window", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ value: "12.5" }] });
    const pool = { query };

    const value = await evaluateAlertRuleMetric(pool as never, rule);

    expect(value).toBe(12.5);
  });

  it("returns null when there is no traffic in the window", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ value: null }] });
    const pool = { query };

    const value = await evaluateAlertRuleMetric(pool as never, rule);

    expect(value).toBeNull();
  });

  it("computes p95 latency", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ value: "1240" }] });
    const pool = { query };

    const value = await evaluateAlertRuleMetric(pool as never, { ...rule, metric: "p95_latency_ms" });

    expect(value).toBe(1240);
  });

  it("computes request count as a plain integer", async () => {
    const query = vi.fn().mockResolvedValue({ rows: [{ value: 12500 }] });
    const pool = { query };

    const value = await evaluateAlertRuleMetric(pool as never, { ...rule, metric: "request_count" });

    expect(value).toBe(12500);
  });

  it("returns null for an unknown metric without querying", async () => {
    const query = vi.fn();
    const pool = { query };

    const value = await evaluateAlertRuleMetric(pool as never, { ...rule, metric: "unknown_metric" });

    expect(value).toBeNull();
    expect(query).not.toHaveBeenCalled();
  });
});

describe("evaluateAlertRules", () => {
  it("raises an incident only for rules that breach their threshold", async () => {
    const query = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          { id: "rule-1", project_id: "demo", metric: "error_rate_percent", threshold: 5, window_minutes: 5 },
          { id: "rule-2", project_id: "demo", metric: "p95_latency_ms", threshold: 1000, window_minutes: 5 }
        ]
      })
      .mockResolvedValueOnce({ rows: [{ value: "12.5" }] })
      .mockResolvedValueOnce({ rows: [{ value: "400" }] });
    const pool = { query };
    const raiseIncident = vi.fn().mockResolvedValue(undefined);

    await evaluateAlertRules(pool as never, raiseIncident);

    expect(raiseIncident).toHaveBeenCalledOnce();
    expect(raiseIncident).toHaveBeenCalledWith(
      pool,
      expect.objectContaining({ id: "rule-1", metric: "error_rate_percent" }),
      12.5
    );
  });

  it("does not raise an incident when no rules are enabled", async () => {
    const query = vi.fn().mockResolvedValueOnce({ rows: [] });
    const pool = { query };
    const raiseIncident = vi.fn();

    await evaluateAlertRules(pool as never, raiseIncident);

    expect(raiseIncident).not.toHaveBeenCalled();
  });
});
