import pg from "pg";
import { withSpan } from "@sentinel/shared";
import {
  AlertDeliveryDetails,
  claimAlertDeliveries,
  markAlertDeliveryFailed,
  markAlertDeliverySucceeded
} from "./db.js";

const DELIVERY_TIMEOUT_MS = 5000;

export async function deliverPendingAlerts(pool: pg.Pool, limit = 10) {
  const deliveries = await claimAlertDeliveries(pool, limit);

  for (const delivery of deliveries) {
    await withSpan(
      "sentinel.worker.deliver_alert",
      {
        "sentinel.delivery_id": delivery.id,
        "sentinel.incident_id": delivery.incident_id
      },
      async () => {
        try {
          await sendAlertWebhook(delivery);
          await markAlertDeliverySucceeded(pool, delivery.id);
        } catch (error) {
          const message = error instanceof Error ? error.message : "unknown_delivery_error";
          await markAlertDeliveryFailed(pool, delivery.id, delivery.attempts, message);
        }
      }
    );
  }
}

async function sendAlertWebhook(delivery: AlertDeliveryDetails) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DELIVERY_TIMEOUT_MS);

  try {
    const response = await fetch(delivery.destination_url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        event: "incident.alert",
        incident: {
          id: delivery.incident_id,
          title: delivery.title,
          severity: delivery.severity,
          description: delivery.description,
          affectedEndpoint: delivery.affected_endpoint,
          attackerIps: delivery.attacker_ips,
          requestCount: delivery.request_count,
          startedAt: delivery.started_at
        },
        destination: { name: delivery.destination_name }
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error(`webhook_status_${response.status}`);
    }
  } finally {
    clearTimeout(timeout);
  }
}
