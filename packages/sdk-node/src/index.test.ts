import { EventEmitter } from "node:events";
import type { Request, Response } from "express";
import { describe, expect, it, vi } from "vitest";
import { SentinelClient, sentinelErrorHandler, sentinelExpress } from "./index.js";

function createFakeRequest(overrides: Partial<Request> = {}): Request {
  return {
    method: "GET",
    path: "/api/users/42",
    ip: "203.0.113.5",
    headers: {},
    query: {},
    body: {},
    ...overrides
  } as unknown as Request;
}

function createFakeResponse(statusCode: number): Response {
  const res = new EventEmitter() as unknown as Response & { statusCode: number };
  res.statusCode = statusCode;
  res.write = vi.fn().mockReturnValue(true) as unknown as Response["write"];
  res.end = vi.fn(function (this: EventEmitter) {
    this.emit("finish");
    return this;
  }) as unknown as Response["end"];
  return res;
}

describe("sentinelExpress error capture", () => {
  it("attaches the caught error to the request and forwards it to next", () => {
    const handler = sentinelErrorHandler();
    const req = createFakeRequest();
    const next = vi.fn();
    const error = new TypeError("Cannot read property 'email' of undefined");

    handler(error, req, createFakeResponse(500), next);

    expect((req as Request & { sentinelError?: unknown }).sentinelError).toBe(error);
    expect(next).toHaveBeenCalledWith(error);
  });

  it("captures the error type, message, and stack on the emitted event", () => {
    const captured: unknown[] = [];
    vi.spyOn(SentinelClient.prototype, "capture").mockImplementation(function (event) {
      captured.push(event);
    });

    const middleware = sentinelExpress({
      projectId: "demo",
      apiKey: "dev-sentinel-key",
      endpoint: "http://localhost:8080",
      serviceName: "example-api"
    });
    const errorHandler = sentinelErrorHandler();
    const req = createFakeRequest();
    const res = createFakeResponse(500);
    const next = vi.fn();
    const error = new TypeError("Cannot read property 'email' of undefined");

    middleware(req, res, next);
    errorHandler(error, req, res, next);
    res.end();

    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      error: {
        type: "TypeError",
        message: "Cannot read property 'email' of undefined"
      }
    });
    expect((captured[0] as { error: { stack?: string } }).error.stack).toContain("TypeError");

    vi.restoreAllMocks();
  });

  it("does not add an error field when the request succeeds", () => {
    const captured: unknown[] = [];
    vi.spyOn(SentinelClient.prototype, "capture").mockImplementation(function (event) {
      captured.push(event);
    });

    const middleware = sentinelExpress({
      projectId: "demo",
      apiKey: "dev-sentinel-key",
      endpoint: "http://localhost:8080",
      serviceName: "example-api"
    });
    const req = createFakeRequest();
    const res = createFakeResponse(200);
    const next = vi.fn();

    middleware(req, res, next);
    res.end();

    expect(captured).toHaveLength(1);
    expect(captured[0]).not.toHaveProperty("error");

    vi.restoreAllMocks();
  });
});
