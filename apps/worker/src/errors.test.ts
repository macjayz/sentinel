import { describe, expect, it } from "vitest";
import { SentinelEvent } from "@sentinel/shared";
import { fingerprintError } from "./errors.js";

const baseEvent: SentinelEvent = {
  id: "event-1",
  projectId: "demo",
  serviceName: "api",
  environment: "test",
  timestamp: new Date().toISOString(),
  kind: "rest",
  request: {
    method: "POST",
    path: "/api/users",
    route: "/api/users/:id",
    headers: {},
    query: {},
    auth: { present: false, failed: false }
  },
  response: { statusCode: 500, latencyMs: 40 }
};

describe("fingerprintError", () => {
  it("returns null when the event has no captured error", () => {
    expect(fingerprintError(baseEvent)).toBeNull();
  });

  it("groups the same error type and message on the same endpoint together", () => {
    const eventA: SentinelEvent = {
      ...baseEvent,
      id: "event-a",
      error: { type: "TypeError", message: "Cannot read property 'email' of undefined" }
    };
    const eventB: SentinelEvent = {
      ...baseEvent,
      id: "event-b",
      error: { type: "TypeError", message: "Cannot read property 'email' of undefined" }
    };

    expect(fingerprintError(eventA)?.key).toBe(fingerprintError(eventB)?.key);
  });

  it("groups messages that only differ by a dynamic id", () => {
    const eventA: SentinelEvent = {
      ...baseEvent,
      error: { type: "Error", message: "User 4821 not found" }
    };
    const eventB: SentinelEvent = {
      ...baseEvent,
      error: { type: "Error", message: "User 9042 not found" }
    };

    expect(fingerprintError(eventA)?.key).toBe(fingerprintError(eventB)?.key);
  });

  it("keeps different error types on the same endpoint separate", () => {
    const typeError: SentinelEvent = {
      ...baseEvent,
      error: { type: "TypeError", message: "Cannot read property 'email' of undefined" }
    };
    const rangeError: SentinelEvent = {
      ...baseEvent,
      error: { type: "RangeError", message: "Cannot read property 'email' of undefined" }
    };

    expect(fingerprintError(typeError)?.key).not.toBe(fingerprintError(rangeError)?.key);
  });

  it("keeps the same error separate across different endpoints", () => {
    const usersEvent: SentinelEvent = {
      ...baseEvent,
      error: { type: "TypeError", message: "Cannot read property 'email' of undefined" }
    };
    const ordersEvent: SentinelEvent = {
      ...baseEvent,
      request: { ...baseEvent.request, route: "/api/orders/:id" },
      error: { type: "TypeError", message: "Cannot read property 'email' of undefined" }
    };

    expect(fingerprintError(usersEvent)?.key).not.toBe(fingerprintError(ordersEvent)?.key);
  });
});
