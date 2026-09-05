import { afterEach, describe, expect, it, vi } from "vitest";
import { deliverPendingAlerts } from "./alerts.js";

const deliveryRow = {
  id: "delivery-1",
  attempts: 0,
  destination_url: "https://alerts.example.com/sentinel",
  destination_name: "Security Operations",
  incident_id: "incident-1",
  title: "Potential credential stuffing on POST /login",
  severity: "high",
  description: "Repeated authentication failures were observed against the same endpoint.",
  affected_endpoint: "POST /login",
  attacker_ips: ["203.0.113.10"],
  request_count: 12,
  started_at: "2026-09-05T20:00:00.000Z"
};

function poolWithClaimResult() {
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rows: [{ id: deliveryRow.id }] })
    .mockResolvedValueOnce({ rows: [deliveryRow] })
    .mockResolvedValue({ rows: [] });

  return { query };
}

describe("deliverPendingAlerts", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("marks a delivery as delivered when the webhook responds with a 2xx status", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 200 }));
    const pool = poolWithClaimResult();

    await deliverPendingAlerts(pool as never);

    const [fetchUrl, fetchInit] = (globalThis.fetch as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(fetchUrl).toBe(deliveryRow.destination_url);
    expect(JSON.parse(fetchInit.body).incident.id).toBe(deliveryRow.incident_id);

    const finalUpdateSql = pool.query.mock.calls.at(-1)?.[0] as string;
    expect(finalUpdateSql).toContain("status = 'delivered'");
  });

  it("requeues a failed delivery with backoff instead of dropping it", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 500 }));
    const pool = poolWithClaimResult();

    await deliverPendingAlerts(pool as never);

    const finalUpdateSql = pool.query.mock.calls.at(-1)?.[0] as string;
    const finalUpdateParams = pool.query.mock.calls.at(-1)?.[1] as unknown[];
    expect(finalUpdateSql).toContain("status = 'queued'");
    expect(finalUpdateParams[1]).toBe(1);
    expect(finalUpdateParams[2]).toBe("webhook_status_500");
  });

  it("marks a delivery failed once retries are exhausted", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(null, { status: 500 }));
    const pool = poolWithClaimResult();
    pool.query.mockReset();
    pool.query
      .mockResolvedValueOnce({ rows: [{ id: deliveryRow.id }] })
      .mockResolvedValueOnce({ rows: [{ ...deliveryRow, attempts: 4 }] })
      .mockResolvedValue({ rows: [] });

    await deliverPendingAlerts(pool as never);

    const finalUpdateSql = pool.query.mock.calls.at(-1)?.[0] as string;
    expect(finalUpdateSql).toContain("status = 'failed'");
  });
});
