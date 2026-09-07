import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import Fastify, { FastifyRequest } from "fastify";
import { z } from "zod";
import { EventBatchSchema, withSpan } from "@sentinel/shared";
import { roleMeetsMinimum, verifyPassword } from "./auth.js";
import { loadConfig } from "./config.js";
import {
  AlertRuleMetrics,
  createAlertDestination,
  createAlertRule,
  createApiKey,
  createPool,
  createSession,
  createWorkspaceOwner,
  deleteSession,
  ensureBootstrapUser,
  getIncidentTimeline,
  getIncidents,
  getOverview,
  getProjectRole,
  getRequests,
  getUserByEmail,
  listAlertDeliveries,
  listAlertDestinations,
  listAlertRules,
  listApiKeys,
  listErrorGroups,
  listMembershipsForUser,
  revokeApiKey,
  resolveProjectForApiKey,
  resolveSession,
  updateAlertDestination,
  updateAlertRule,
  updateIncidentStatus
} from "./db.js";
import { attachLiveServer } from "./live.js";
import {
  buildMetricsSnapshot,
  buildReadiness,
  createRuntimeMetrics,
  toPrometheus
} from "./observability.js";
import { createRedis, enqueueEvents } from "./queue.js";

export async function buildServer() {
  const config = loadConfig();
  const app = Fastify({ logger: true });
  const pool = createPool(config);
  const redis = createRedis(config);
  const metrics = createRuntimeMetrics();
  const liveHub = attachLiveServer(app.server, async (token, projectId) => {
    if (!projectId) return false;
    const session = await resolveSession(pool, token);
    if (!session) return false;
    return Boolean(await getProjectRole(pool, session.userId, projectId));
  });

  if (config.bootstrapDemoUser) {
    await ensureBootstrapUser(pool, "demo", config.adminEmail, config.adminPassword);
  }

  await app.register(cors, { origin: true });
  await app.register(rateLimit, { max: 600, timeWindow: "1 minute" });

  app.addHook("onRequest", async (request, reply) => {
    metrics.totalRequests += 1;
    reply.header("x-request-id", request.id);

    return;
  });

  app.addHook("onResponse", async (_request, reply) => {
    const bucket = String(reply.statusCode);
    metrics.responseBuckets[bucket] = (metrics.responseBuckets[bucket] ?? 0) + 1;
  });

  app.get("/health", async () => ({ ok: true }));
  app.get("/ready", async () => buildReadiness(pool, redis, config.streamName, config.groupName));
  app.get("/metrics", async (_request, reply) => {
    const snapshot = await buildMetricsSnapshot(metrics, pool, redis, config.streamName, config.groupName, liveHub);
    reply.header("content-type", "text/plain; version=0.0.4").send(toPrometheus(snapshot));
  });

  app.post("/v1/events", async (request, reply) => {
    return withSpan(
      "sentinel.ingestion.accept_batch",
      {
        "http.request_id": request.id,
        "http.route": "/v1/events"
      },
      async () => {
        const apiKey = String(request.headers["x-sentinel-api-key"] ?? "");
        const key = await resolveProjectForApiKey(
          pool,
          apiKey,
          config.sentinelApiKey,
          undefined,
          config.allowDevFallbackApiKey
        );
        if (!key) {
          return reply.code(401).send({ error: "invalid_api_key" });
        }

        const parsed = EventBatchSchema.safeParse(request.body);
        if (!parsed.success) {
          metrics.failedIngestionBatches += 1;
          return reply.code(400).send({ error: "invalid_event_batch", details: parsed.error.flatten() });
        }

        const hasProjectMismatch = parsed.data.events.some((event) => event.projectId !== key.projectId);
        if (hasProjectMismatch) {
          return reply.code(403).send({ error: "project_scope_mismatch" });
        }

        await enqueueEvents(redis, config.streamName, parsed.data.events);
        metrics.ingestionBatches += 1;
        metrics.ingestionEvents += parsed.data.events.length;
        liveHub.publishToProject("events.accepted", { count: parsed.data.events.length }, key.projectId);
        return reply.code(202).send({ accepted: parsed.data.events.length });
      }
    );
  });

  app.post(
    "/v1/auth/signup",
    {
      config: {
        rateLimit: {
          max: 6,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      const parsed = SignupSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_signup_payload", details: parsed.error.flatten() });
      }

      const workspace = await createWorkspaceOwner(pool, parsed.data);
      if (workspace.kind === "email_exists") {
        return reply.code(409).send({ error: "email_already_registered" });
      }

      const session = await createSession(pool, workspace.user.id);
      return reply.code(201).send({
        token: session.token,
        expiresAt: session.expiresAt,
        user: workspace.user,
        organization: workspace.organization,
        projects: [workspace.project],
        apiKey: workspace.apiKey
      });
    }
  );

  app.post(
    "/v1/auth/login",
    {
      config: {
        rateLimit: {
          max: 10,
          timeWindow: "1 minute"
        }
      }
    },
    async (request, reply) => {
      const parsed = LoginSchema.safeParse(request.body);
      if (!parsed.success) {
        return reply.code(400).send({ error: "invalid_login_payload", details: parsed.error.flatten() });
      }

      const user = await getUserByEmail(pool, parsed.data.email);
      if (!user || !(await verifyPassword(parsed.data.password, user.password_hash))) {
        return reply.code(401).send({ error: "invalid_credentials" });
      }

      const session = await createSession(pool, user.id);
      const memberships = await listMembershipsForUser(pool, user.id);

      return reply.code(200).send({
        token: session.token,
        expiresAt: session.expiresAt,
        user: { id: user.id, email: user.email },
        organization: { id: user.organization_id, name: user.organization_name },
        projects: memberships.map((membership) => ({
          id: membership.project_id,
          name: membership.name,
          role: membership.role
        }))
      });
    }
  );

  app.get("/v1/auth/session", async (request, reply) => {
    const session = await resolveSession(pool, getBearerToken(request));
    if (!session) return reply.code(401).send({ error: "invalid_session" });

    const memberships = await listMembershipsForUser(pool, session.userId);
    return {
      user: { id: session.userId, email: session.email },
      organization: { id: session.organizationId, name: session.organizationName },
      projects: memberships.map((membership) => ({
        id: membership.project_id,
        name: membership.name,
        role: membership.role
      }))
    };
  });

  app.post("/v1/auth/logout", async (request, reply) => {
    const token = getBearerToken(request);
    if (token) await deleteSession(pool, token);
    return reply.code(204).send();
  });

  app.get("/v1/analytics/overview", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return getOverview(pool, scope.projectId);
  });
  app.get("/v1/analytics/incidents", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return getIncidents(pool, scope.projectId);
  });
  app.get("/v1/analytics/requests", async (request, reply) => {
    const query = request.query as {
      kind?: string;
      method?: string;
      status?: string;
      threatMin?: string;
      ip?: string;
      q?: string;
      limit?: string;
    };
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;

    return getRequests(pool, {
      projectId: scope.projectId,
      kind: query.kind,
      method: query.method,
      status: query.status ? Number(query.status) : undefined,
      threatMin: query.threatMin ? Number(query.threatMin) : undefined,
      ip: query.ip,
      query: query.q,
      limit: query.limit ? Number(query.limit) : undefined
    });
  });
  app.get("/v1/analytics/system", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return buildMetricsSnapshot(metrics, pool, redis, config.streamName, config.groupName, liveHub);
  });

  app.get("/v1/api-keys", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return listApiKeys(pool, scope.projectId);
  });

  app.post("/v1/api-keys", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "admin");
    if (!scope) return;

    const parsed = CreateApiKeySchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_api_key_payload", details: parsed.error.flatten() });
    }

    const key = await createApiKey(pool, scope.projectId, parsed.data.name);
    return reply.code(201).send(key);
  });

  app.delete("/v1/api-keys/:id", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "admin");
    if (!scope) return;

    const { id } = request.params as { id: string };
    const revoked = await revokeApiKey(pool, scope.projectId, id);
    if (!revoked) return reply.code(404).send({ error: "api_key_not_found" });
    return reply.code(204).send();
  });

  app.patch("/v1/incidents/:id/status", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "developer");
    if (!scope) return;

    const parsed = UpdateIncidentStatusSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_incident_status_payload", details: parsed.error.flatten() });
    }

    const { id } = request.params as { id: string };
    const incident = await updateIncidentStatus(
      pool,
      scope.projectId,
      id,
      parsed.data.status,
      "demo-operator",
      parsed.data.note
    );
    if (!incident) return reply.code(404).send({ error: "incident_not_found" });
    liveHub.publishToProject("incident.updated", { id, status: parsed.data.status }, scope.projectId);
    return incident;
  });

  app.get("/v1/incidents/:id/timeline", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;

    const { id } = request.params as { id: string };
    return getIncidentTimeline(pool, scope.projectId, id);
  });

  app.get("/v1/alert-destinations", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return listAlertDestinations(pool, scope.projectId);
  });

  app.post("/v1/alert-destinations", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "admin");
    if (!scope) return;

    const parsed = CreateAlertDestinationSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_alert_destination_payload", details: parsed.error.flatten() });
    }

    const destination = await createAlertDestination(pool, scope.projectId, parsed.data.name, parsed.data.url);
    return reply.code(201).send(destination);
  });

  app.patch("/v1/alert-destinations/:id", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "admin");
    if (!scope) return;

    const parsed = UpdateAlertDestinationSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_alert_destination_payload", details: parsed.error.flatten() });
    }

    const { id } = request.params as { id: string };
    const destination = await updateAlertDestination(pool, scope.projectId, id, parsed.data.enabled);
    if (!destination) return reply.code(404).send({ error: "alert_destination_not_found" });
    return destination;
  });

  app.get("/v1/alert-deliveries", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return listAlertDeliveries(pool, scope.projectId);
  });

  app.get("/v1/alert-rules", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return listAlertRules(pool, scope.projectId);
  });

  app.get("/v1/errors", async (request, reply) => {
    const scope = await requireProjectScope(pool, config.sentinelApiKey, config.allowDevFallbackApiKey, request, reply);
    if (!scope) return;
    return listErrorGroups(pool, scope.projectId);
  });

  app.post("/v1/alert-rules", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "admin");
    if (!scope) return;

    const parsed = CreateAlertRuleSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_alert_rule_payload", details: parsed.error.flatten() });
    }

    const rule = await createAlertRule(
      pool,
      scope.projectId,
      parsed.data.metric,
      parsed.data.threshold,
      parsed.data.windowMinutes
    );
    return reply.code(201).send(rule);
  });

  app.patch("/v1/alert-rules/:id", async (request, reply) => {
    const scope = await requireDashboardProjectScope(pool, request, reply, "admin");
    if (!scope) return;

    const parsed = UpdateAlertRuleSchema.safeParse(request.body);
    if (!parsed.success) {
      return reply.code(400).send({ error: "invalid_alert_rule_payload", details: parsed.error.flatten() });
    }

    const { id } = request.params as { id: string };
    const rule = await updateAlertRule(pool, scope.projectId, id, parsed.data);
    if (!rule) return reply.code(404).send({ error: "alert_rule_not_found" });
    return rule;
  });

  app.addHook("onClose", async () => {
    liveHub.close();
    await redis.quit();
    await pool.end();
  });

  return { app, config };
}

const LoginSchema = z.object({
  email: z.string().trim().email().transform((value) => value.toLowerCase()),
  password: z.string().min(1)
});

const SignupSchema = z.object({
  email: z.string().trim().email().transform((value) => value.toLowerCase()),
  password: z.string().min(8).max(128),
  organizationName: z.string().trim().min(2).max(80),
  projectName: z.string().trim().min(2).max(80)
});

const CreateApiKeySchema = z.object({
  name: z.string().trim().min(2).max(80)
});

const UpdateIncidentStatusSchema = z.object({
  status: z.enum(["open", "acknowledged", "resolved", "ignored"]),
  note: z.string().trim().max(500).optional()
});

const CreateAlertDestinationSchema = z.object({
  name: z.string().trim().min(2).max(80),
  url: z.string().url().refine((url) => url.startsWith("https://") || url.startsWith("http://localhost"), {
    message: "Webhook URLs must use HTTPS unless they point at localhost."
  })
});

const UpdateAlertDestinationSchema = z.object({
  enabled: z.boolean()
});

const CreateAlertRuleSchema = z.object({
  metric: z.enum(AlertRuleMetrics),
  threshold: z.number().positive(),
  windowMinutes: z.number().int().min(1).max(1440).default(5)
});

const UpdateAlertRuleSchema = z
  .object({
    enabled: z.boolean().optional(),
    threshold: z.number().positive().optional(),
    windowMinutes: z.number().int().min(1).max(1440).optional()
  })
  .refine((value) => value.enabled !== undefined || value.threshold !== undefined || value.windowMinutes !== undefined, {
    message: "At least one of enabled, threshold, or windowMinutes must be provided."
  });

type ProjectScope = {
  projectId: string;
  keyId?: string;
  userId?: string;
};

async function requireProjectScope(
  pool: ReturnType<typeof createPool>,
  fallbackApiKey: string,
  allowFallbackApiKey: boolean,
  request: FastifyRequest,
  reply: import("fastify").FastifyReply
): Promise<ProjectScope | null> {
  const sessionScope = await getSessionProjectScope(pool, request, reply);
  if (sessionScope) return sessionScope;
  if (reply.sent) return null;

  const apiKeyHeader = request.headers["x-sentinel-api-key"];
  if (!apiKeyHeader) {
    reply.code(401).send({ error: "authentication_required" });
    return null;
  }
  const requestedProjectId = (request.query as { projectId?: string } | undefined)?.projectId;
  const apiKey = Array.isArray(apiKeyHeader) ? apiKeyHeader[0] : apiKeyHeader;
  const scope = await resolveProjectForApiKey(pool, apiKey, fallbackApiKey, requestedProjectId, allowFallbackApiKey);
  if (!scope) {
    reply.code(401).send({ error: "invalid_api_key" });
    return null;
  }
  return scope;
}

function getBearerToken(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  if (!header?.startsWith("Bearer ")) return undefined;
  return header.slice("Bearer ".length);
}

async function requireDashboardProjectScope(
  pool: ReturnType<typeof createPool>,
  request: FastifyRequest,
  reply: import("fastify").FastifyReply,
  minimumRole: string
): Promise<ProjectScope | null> {
  return getSessionProjectScope(pool, request, reply, minimumRole);
}

async function getSessionProjectScope(
  pool: ReturnType<typeof createPool>,
  request: FastifyRequest,
  reply: import("fastify").FastifyReply,
  minimumRole?: string
): Promise<ProjectScope | null> {
  const token = getBearerToken(request);
  if (!token) return null;

  const session = await resolveSession(pool, token);
  if (!session) {
    reply.code(401).send({ error: "invalid_session" });
    return null;
  }

  const requestedProjectId = (request.query as { projectId?: string } | undefined)?.projectId;
  const memberships = await listMembershipsForUser(pool, session.userId);
  const membership =
    memberships.find((entry) => entry.project_id === requestedProjectId) ??
    (!requestedProjectId ? memberships[0] : undefined);

  if (!membership) {
    reply.code(403).send({ error: "project_access_denied" });
    return null;
  }

  const projectId = membership.project_id as string;
  const role = await getProjectRole(pool, session.userId, projectId);
  if (minimumRole && !roleMeetsMinimum(role, minimumRole)) {
    reply.code(403).send({ error: "insufficient_role", required: minimumRole });
    return null;
  }

  return { projectId, userId: session.userId };
}

if (process.env.NODE_ENV !== "test") {
  const { app, config } = await buildServer();
  await app.listen({ port: config.port, host: "0.0.0.0" });
}
