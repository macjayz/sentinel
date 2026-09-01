import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Building2,
  Clock,
  Copy,
  Database,
  Filter,
  Gauge,
  Globe2,
  KeyRound,
  LogOut,
  Plus,
  Radio,
  RefreshCcw,
  Search,
  ShieldCheck,
  Trash2,
  User
} from "lucide-react";
import "./styles.css";

type Overview = {
  totals: {
    events: number;
    openIncidents: number;
    averageLatencyMs: number;
  };
  endpoints: Array<{
    path: string;
    method: string;
    requests: number;
    latency: number;
    max_threat_score: number;
  }>;
  ips: Array<{
    ip: string;
    requests: number;
    max_threat_score: number;
  }>;
};

type Incident = {
  id: string;
  incident_key?: string;
  severity: string;
  title: string;
  description: string;
  status: string;
  affected_endpoint?: string;
  attacker_ips?: string[];
  request_count?: number;
  started_at?: string;
  last_seen_at?: string;
  created_at: string;
};

type Readiness = {
  status: "ready" | "degraded";
  checks: {
    database: { ok: boolean; latencyMs: number };
    queue: { ok: boolean; latencyMs: number; depth: number };
  };
};

type SystemMetrics = {
  uptimeSeconds: number;
  totalRequests: number;
  ingestionRate: number;
  ingestionBatches: number;
  failedJobs: number;
  queueDepth: number;
  databaseLatencyMs: number;
  processingLatencyMs: number;
  websocketConnections: number;
};

type RequestRecord = {
  id: string;
  trace_id?: string;
  parent_span_id?: string;
  timestamp: string;
  service_name: string;
  environment: string;
  kind: string;
  method: string;
  path: string;
  route?: string;
  ip?: string;
  user_agent?: string;
  status_code: number;
  latency_ms: number;
  body_bytes?: number;
  auth_present: boolean;
  auth_failed: boolean;
  graphql_operation_name?: string;
  graphql_operation_type?: string;
  evm_rpc_method?: string;
  threat_score: number;
  threat_severity: string;
};

type RequestFilters = {
  method: string;
  status: string;
  threatMin: string;
  ip: string;
  query: string;
};

type ApiKeyRecord = {
  id: string;
  name: string;
  prefix: string;
  key?: string;
  last_used_at?: string | null;
  created_at: string;
  revoked_at?: string | null;
};

type DashboardView = "overview" | "requests" | "incidents" | "api-keys";

type ProjectOption = {
  id: string;
  name: string;
  role: "owner" | "admin" | "developer" | "viewer";
};

type AuthSession = {
  user: {
    name: string;
    email: string;
  };
  organization: {
    id: string;
    name: string;
  };
  projects: ProjectOption[];
};

const apiBase = import.meta.env.VITE_SENTINEL_API_URL ?? "http://localhost:8080";
const dashboardApiKey = import.meta.env.VITE_SENTINEL_API_KEY;

function App() {
  const [activeView, setActiveView] = useState<DashboardView>(
    getInitialView()
  );
  const [isAuthenticated, setIsAuthenticated] = useState(
    () => window.localStorage.getItem("sentinel.dashboard.session") === "active"
  );
  const [session] = useState<AuthSession>(demoSession);
  const [selectedProjectId, setSelectedProjectId] = useState(
    () => window.localStorage.getItem("sentinel.dashboard.project") ?? demoSession.projects[0].id
  );
  const [authForm, setAuthForm] = useState({ email: "owner@sentinel.local", password: "" });
  const [overview, setOverview] = useState<Overview | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [requests, setRequests] = useState<RequestRecord[]>(demoRequests);
  const [apiKeys, setApiKeys] = useState<ApiKeyRecord[]>(demoApiKeys);
  const [newKeyName, setNewKeyName] = useState("Production SDK");
  const [newKeySecret, setNewKeySecret] = useState("");
  const [requestFilters, setRequestFilters] = useState<RequestFilters>({
    method: "",
    status: "",
    threatMin: "",
    ip: "",
    query: ""
  });
  const [readiness, setReadiness] = useState<Readiness>(demoReadiness);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>(demoSystemMetrics);
  const [liveStatus, setLiveStatus] = useState("Connecting");
  const selectedProject =
    session.projects.find((project) => project.id === selectedProjectId) ?? session.projects[0];

  useEffect(() => {
    if (!isAuthenticated) return;

    async function load() {
      try {
        const [overviewResponse, incidentResponse, readinessResponse, systemResponse, apiKeysResponse] = await Promise.all([
          apiFetch("/v1/analytics/overview", selectedProjectId),
          apiFetch("/v1/analytics/incidents", selectedProjectId),
          fetch(`${apiBase}/ready`),
          apiFetch("/v1/analytics/system", selectedProjectId),
          apiFetch("/v1/api-keys", selectedProjectId)
        ]);

        if (
          !overviewResponse.ok ||
          !incidentResponse.ok ||
          !readinessResponse.ok ||
          !systemResponse.ok ||
          !apiKeysResponse.ok
        ) {
          throw new Error("analytics_unavailable");
        }

        setOverview(await overviewResponse.json());
        setIncidents(await incidentResponse.json());
        setReadiness(await readinessResponse.json());
        setSystemMetrics(await systemResponse.json());
        setApiKeys(await apiKeysResponse.json());
        await loadRequests();
      } catch {
        const demoData = getDemoProjectData(selectedProjectId);
        setOverview(demoData.overview);
        setIncidents(demoData.incidents);
        setReadiness(demoReadiness);
        setSystemMetrics(demoSystemMetrics);
        setRequests(filterDemoRequests(demoData.requests, requestFilters));
        setApiKeys(demoData.apiKeys);
      }
    }

    void load();
    const interval = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(interval);
  }, [isAuthenticated, requestFilters, selectedProjectId]);

  async function createDashboardApiKey() {
    try {
      const response = await apiFetch("/v1/api-keys", selectedProjectId, {
        method: "POST",
        body: JSON.stringify({ name: newKeyName })
      });
      if (!response.ok) throw new Error("key_create_failed");
      const key = (await response.json()) as ApiKeyRecord;
      setApiKeys((current) => [key, ...current]);
      setNewKeySecret(key.key ?? "");
    } catch {
      const key = createDemoApiKey(newKeyName);
      setApiKeys((current) => [key, ...current]);
      setNewKeySecret(key.key ?? "");
    }
  }

  async function revokeDashboardApiKey(keyId: string) {
    try {
      const response = await apiFetch(`/v1/api-keys/${keyId}`, selectedProjectId, { method: "DELETE" });
      if (!response.ok) throw new Error("key_revoke_failed");
    } catch {
      // Offline demo mode keeps the interaction local while Docker is unavailable.
    }

    setApiKeys((current) =>
      current.map((key) => (key.id === keyId ? { ...key, revoked_at: new Date().toISOString() } : key))
    );
  }

  async function loadRequests() {
    const params = new URLSearchParams();
    if (requestFilters.method) params.set("method", requestFilters.method);
    if (requestFilters.status) params.set("status", requestFilters.status);
    if (requestFilters.threatMin) params.set("threatMin", requestFilters.threatMin);
    if (requestFilters.ip) params.set("ip", requestFilters.ip);
    if (requestFilters.query) params.set("q", requestFilters.query);
    params.set("limit", "50");

    const response = await apiFetch(`/v1/analytics/requests?${params.toString()}`, selectedProjectId);
    if (!response.ok) throw new Error("requests_unavailable");
    setRequests(await response.json());
  }

  useEffect(() => {
    if (!isAuthenticated) return;

    const liveUrl = apiBase.replace(/^http/, "ws") + "/live";
    const socket = new WebSocket(liveUrl);

    socket.addEventListener("open", () => setLiveStatus("Live"));
    socket.addEventListener("close", () => setLiveStatus("Offline"));
    socket.addEventListener("message", () => setLiveStatus("Event received"));

    return () => socket.close();
  }, [isAuthenticated]);

  const maxThreatScore = useMemo(() => {
    const endpointScores = overview?.endpoints.map((endpoint) => endpoint.max_threat_score) ?? [];
    const ipScores = overview?.ips.map((ip) => ip.max_threat_score) ?? [];
    return Math.max(0, ...endpointScores, ...ipScores);
  }, [overview]);
  const header = getHeader(activeView);

  if (!isAuthenticated) {
    return (
      <AuthScreen
        form={authForm}
        onChange={setAuthForm}
        onSubmit={() => {
          window.localStorage.setItem("sentinel.dashboard.session", "active");
          window.localStorage.setItem("sentinel.dashboard.project", selectedProjectId);
          setIsAuthenticated(true);
        }}
      />
    );
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <div className="brand">
          <ShieldCheck size={28} />
          <div>
            <strong>Sentinel</strong>
            <span>API Security</span>
          </div>
        </div>
        <nav>
          <button className={activeView === "overview" ? "active" : ""} onClick={() => changeView("overview")}>
            Overview
          </button>
          <button className={activeView === "requests" ? "active" : ""} onClick={() => changeView("requests")}>
            Requests
          </button>
          <button className={activeView === "incidents" ? "active" : ""} onClick={() => changeView("incidents")}>
            Incidents
          </button>
          <button className={activeView === "api-keys" ? "active" : ""} onClick={() => changeView("api-keys")}>
            API Keys
          </button>
          <button className="disabled" disabled>
            Sources
          </button>
        </nav>

        <div className="operator-card">
          <span>
            <User size={16} />
          </span>
          <div>
            <strong>{session.user.name}</strong>
            <p>{selectedProject.role}</p>
          </div>
        </div>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>{header.title}</h1>
            <p>{header.subtitle}</p>
          </div>
          <div className="topbar-actions">
            <label className="project-switcher">
              <Building2 size={16} />
              <select
                value={selectedProjectId}
                onChange={(event) => {
                  window.localStorage.setItem("sentinel.dashboard.project", event.target.value);
                  setSelectedProjectId(event.target.value);
                }}
              >
                {session.projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
            </label>
            <div className={`live-pill ${liveStatus.toLowerCase().replace(/\s+/g, "-")}`}>
              <Radio size={16} />
              {liveStatus}
            </div>
            <button
              className="icon-button"
              onClick={() => {
                window.localStorage.removeItem("sentinel.dashboard.session");
                setIsAuthenticated(false);
              }}
              title="Sign out"
            >
              <LogOut size={16} />
            </button>
          </div>
        </header>

        <section className="metrics">
          <Metric label="Events" value={overview?.totals.events ?? 0} icon={<Activity size={18} />} />
          <Metric
            label="Open Incidents"
            value={overview?.totals.openIncidents ?? 0}
            icon={<AlertTriangle size={18} />}
          />
          <Metric
            label="Average Latency"
            value={`${overview?.totals.averageLatencyMs ?? 0}ms`}
            icon={<Clock size={18} />}
          />
          <Metric label="Max Threat Score" value={maxThreatScore} icon={<ShieldCheck size={18} />} />
        </section>

        <section className="system-strip">
          <StatusItem
            label="Readiness"
            value={readiness.status}
            active={readiness.status === "ready"}
            icon={<ShieldCheck size={16} />}
          />
          <StatusItem
            label="Database"
            value={formatLatency(readiness.checks.database.latencyMs)}
            active={readiness.checks.database.ok}
            icon={<Database size={16} />}
          />
          <StatusItem
            label="Queue Depth"
            value={formatCount(systemMetrics.queueDepth)}
            active={readiness.checks.queue.ok}
            icon={<Gauge size={16} />}
          />
          <StatusItem
            label="WebSockets"
            value={systemMetrics.websocketConnections}
            active={systemMetrics.websocketConnections >= 0}
            icon={<Radio size={16} />}
          />
          <StatusItem
            label="Failed Jobs"
            value={systemMetrics.failedJobs}
            active={systemMetrics.failedJobs === 0}
            icon={<AlertTriangle size={16} />}
          />
        </section>

        {activeView === "overview" && (
          <>
            <section className="grid">
              <Panel title="Endpoint Discovery">
                <table>
                  <thead>
                    <tr>
                      <th>Method</th>
                      <th>Path</th>
                      <th>Requests</th>
                      <th>Latency</th>
                      <th>Threat</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(overview?.endpoints ?? []).map((endpoint) => (
                      <tr key={`${endpoint.method}:${endpoint.path}`}>
                        <td>{endpoint.method}</td>
                        <td>{endpoint.path}</td>
                        <td>{endpoint.requests}</td>
                        <td>{Math.round(endpoint.latency ?? 0)}ms</td>
                        <td>{endpoint.max_threat_score}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </Panel>

              <Panel title="IP Activity">
                <div className="ip-list">
                  {(overview?.ips ?? []).map((entry) => (
                    <div className="ip-row" key={entry.ip}>
                      <Globe2 size={16} />
                      <span>{entry.ip}</span>
                      <strong>{entry.requests}</strong>
                      <meter min="0" max="100" value={entry.max_threat_score} />
                    </div>
                  ))}
                </div>
              </Panel>
            </section>

            <IncidentPanel incidents={incidents} />
          </>
        )}

        {activeView === "requests" && (
          <RequestExplorer
            filters={requestFilters}
            requests={requests}
            onChange={setRequestFilters}
            onRefresh={() =>
              void loadRequests().catch(() =>
                setRequests(filterDemoRequests(getDemoProjectData(selectedProjectId).requests, requestFilters))
              )
            }
          />
        )}

        {activeView === "incidents" && <IncidentPanel incidents={incidents} />}

        {activeView === "api-keys" && (
          <ApiKeyPanel
            apiKeys={apiKeys}
            keyName={newKeyName}
            keySecret={newKeySecret}
            selectedProject={selectedProject}
            onKeyNameChange={setNewKeyName}
            onCreate={() => void createDashboardApiKey()}
            onRevoke={(keyId) => void revokeDashboardApiKey(keyId)}
          />
        )}
      </section>
    </main>
  );

  function changeView(view: DashboardView) {
    setActiveView(view);
    const url = new URL(window.location.href);
    url.searchParams.set("view", view);
    window.history.replaceState(null, "", url);
  }
}

function AuthScreen(props: {
  form: { email: string; password: string };
  onChange: (form: { email: string; password: string }) => void;
  onSubmit: () => void;
}) {
  const canSubmit = props.form.email.length > 0 && props.form.password.length > 0;

  return (
    <main className="auth-shell">
      <section className="auth-panel">
        <div className="brand auth-brand">
          <ShieldCheck size={30} />
          <div>
            <strong>Sentinel</strong>
            <span>API Security</span>
          </div>
        </div>
        <div>
          <h1>Sign in to Sentinel</h1>
          <p>Access the operator dashboard with project-scoped telemetry and incidents.</p>
        </div>
        <form
          className="auth-form"
          onSubmit={(event) => {
            event.preventDefault();
            if (canSubmit) props.onSubmit();
          }}
        >
          <label>
            Email
            <input
              type="email"
              value={props.form.email}
              onChange={(event) => props.onChange({ ...props.form, email: event.target.value })}
              placeholder="owner@sentinel.local"
            />
          </label>
          <label>
            Password
            <input
              type="password"
              value={props.form.password}
              onChange={(event) => props.onChange({ ...props.form, password: event.target.value })}
              placeholder="Enter a demo password"
            />
          </label>
          <button disabled={!canSubmit}>
            <KeyRound size={16} />
            Sign in
          </button>
        </form>
      </section>

      <aside className="auth-context">
        <span>
          <Building2 size={18} />
        </span>
        <div>
          <strong>Demo Organization</strong>
          <p>Owner role, project memberships, and API key scoping are represented in the dashboard shell.</p>
        </div>
      </aside>
    </main>
  );
}

function Metric(props: { label: string; value: string | number; icon: React.ReactNode }) {
  return (
    <article className="metric">
      <span>{props.icon}</span>
      <div>
        <strong>{props.value}</strong>
        <p>{props.label}</p>
      </div>
    </article>
  );
}

function Panel(props: { title: string; children: React.ReactNode }) {
  return (
    <section className="panel">
      <h2>{props.title}</h2>
      {props.children}
    </section>
  );
}

function RequestExplorer(props: {
  filters: RequestFilters;
  requests: RequestRecord[];
  onChange: (filters: RequestFilters) => void;
  onRefresh: () => void;
}) {
  const setFilter = (key: keyof RequestFilters, value: string) => {
    props.onChange({ ...props.filters, [key]: value });
  };

  return (
    <Panel title="Request Explorer">
      <div className="filters">
        <label>
          <Search size={15} />
          <input
            value={props.filters.query}
            onChange={(event) => setFilter("query", event.target.value)}
            placeholder="Path or route"
          />
        </label>
        <label>
          <Filter size={15} />
          <select value={props.filters.method} onChange={(event) => setFilter("method", event.target.value)}>
            <option value="">All methods</option>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
            <option value="PUT">PUT</option>
            <option value="PATCH">PATCH</option>
            <option value="DELETE">DELETE</option>
          </select>
        </label>
        <input
          value={props.filters.status}
          inputMode="numeric"
          onChange={(event) => setFilter("status", event.target.value)}
          placeholder="Status"
        />
        <input
          value={props.filters.ip}
          onChange={(event) => setFilter("ip", event.target.value)}
          placeholder="IP address"
        />
        <input
          value={props.filters.threatMin}
          inputMode="numeric"
          onChange={(event) => setFilter("threatMin", event.target.value)}
          placeholder="Min threat"
        />
        <button className="icon-button" onClick={props.onRefresh} title="Refresh request data">
          <RefreshCcw size={16} />
        </button>
      </div>

      <div className="request-table">
        <table>
          <thead>
            <tr>
              <th>Time</th>
              <th>Method</th>
              <th>Route</th>
              <th>Status</th>
              <th>Latency</th>
              <th>IP</th>
              <th>Kind</th>
              <th>Trace</th>
              <th>Threat</th>
            </tr>
          </thead>
          <tbody>
            {props.requests.map((request) => (
              <tr key={request.id}>
                <td>{new Date(request.timestamp).toLocaleTimeString()}</td>
                <td>{request.method}</td>
                <td>
                  <strong>{request.route ?? request.path}</strong>
                  <span>{request.evm_rpc_method ?? request.graphql_operation_name ?? request.service_name}</span>
                </td>
                <td>
                  <span className={`status-code s${Math.floor(request.status_code / 100)}xx`}>
                    {request.status_code}
                  </span>
                </td>
                <td>{request.latency_ms}ms</td>
                <td>{request.ip ?? "N/A"}</td>
                <td>{request.kind}</td>
                <td>{shortTrace(request.trace_id)}</td>
                <td>
                  <meter min="0" max="100" value={request.threat_score} />
                  <span>{request.threat_score}</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function IncidentPanel(props: { incidents: Incident[] }) {
  return (
    <Panel title="Incidents">
      <div className="incident-list">
        {props.incidents.map((incident) => (
          <article className="incident" key={incident.id}>
            <span className={`severity ${incident.severity}`}>{incident.severity}</span>
            <div>
              <strong>{incident.title}</strong>
              <p>{incident.description}</p>
              <div className="incident-meta">
                <span>{incident.affected_endpoint ?? "Endpoint pending"}</span>
                <span>{incident.request_count ?? 1} requests</span>
                <span>{formatIps(incident.attacker_ips)}</span>
              </div>
            </div>
            <time>{new Date(incident.last_seen_at ?? incident.created_at).toLocaleString()}</time>
          </article>
        ))}
      </div>
    </Panel>
  );
}

function ApiKeyPanel(props: {
  apiKeys: ApiKeyRecord[];
  keyName: string;
  keySecret: string;
  selectedProject: ProjectOption;
  onKeyNameChange: (name: string) => void;
  onCreate: () => void;
  onRevoke: (keyId: string) => void;
}) {
  return (
    <Panel title="API Key Management">
      <div className="key-layout">
        <section className="key-create">
          <div>
            <h3>Create project key</h3>
            <p>Generate a scoped SDK key for {props.selectedProject.name}.</p>
          </div>
          <label>
            Key name
            <input value={props.keyName} onChange={(event) => props.onKeyNameChange(event.target.value)} />
          </label>
          <button className="primary-action" onClick={props.onCreate} disabled={props.keyName.trim().length < 2}>
            <Plus size={16} />
            Create key
          </button>
          {props.keySecret && (
            <div className="key-secret">
              <span>New key</span>
              <code>{props.keySecret}</code>
              <button
                className="icon-button"
                onClick={() => void navigator.clipboard?.writeText(props.keySecret)}
                title="Copy new key"
              >
                <Copy size={16} />
              </button>
            </div>
          )}
        </section>

        <section className="sdk-snippet">
          <h3>SDK setup</h3>
          <pre>{`sentinelExpress({
  projectId: "${props.selectedProject.id}",
  apiKey: process.env.SENTINEL_API_KEY,
  endpoint: "http://localhost:8080"
});`}</pre>
        </section>
      </div>

      <div className="key-table">
        <table>
          <thead>
            <tr>
              <th>Name</th>
              <th>Prefix</th>
              <th>Status</th>
              <th>Last Used</th>
              <th>Created</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {props.apiKeys.map((key) => (
              <tr key={key.id}>
                <td>{key.name}</td>
                <td>
                  <code>{key.prefix}</code>
                </td>
                <td>{key.revoked_at ? "Revoked" : "Active"}</td>
                <td>{key.last_used_at ? new Date(key.last_used_at).toLocaleString() : "Never"}</td>
                <td>{new Date(key.created_at).toLocaleDateString()}</td>
                <td>
                  <button
                    className="danger-button"
                    onClick={() => props.onRevoke(key.id)}
                    disabled={Boolean(key.revoked_at)}
                    title="Revoke API key"
                  >
                    <Trash2 size={15} />
                    Revoke
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}

function StatusItem(props: {
  label: string;
  value: string | number;
  active: boolean;
  icon: React.ReactNode;
}) {
  return (
    <article className="status-item">
      <span className={props.active ? "ok" : "bad"}>{props.icon}</span>
      <div>
        <strong>{props.value}</strong>
        <p>{props.label}</p>
      </div>
    </article>
  );
}

createRoot(document.getElementById("root")!).render(<App />);

function formatLatency(value: number) {
  return value < 0 ? "N/A" : `${value}ms`;
}

function formatCount(value: number) {
  return value < 0 ? "N/A" : value;
}

function getInitialView(): DashboardView {
  const view = new URLSearchParams(window.location.search).get("view");
  return view === "requests" || view === "incidents" || view === "api-keys" ? view : "overview";
}

function getHeader(view: DashboardView) {
  if (view === "requests") {
    return {
      title: "Request Explorer",
      subtitle: "Filter recent REST, GraphQL, and EVM JSON-RPC events by risk and behavior."
    };
  }

  if (view === "incidents") {
    return {
      title: "Incidents",
      subtitle: "Review grouped security events and their current severity."
    };
  }

  if (view === "api-keys") {
    return {
      title: "API Keys",
      subtitle: "Create and revoke project-scoped SDK credentials."
    };
  }

  return {
    title: "Security Overview",
    subtitle: "REST, GraphQL, and EVM JSON-RPC telemetry from monitored services."
  };
}

function formatIps(ips?: string[]) {
  if (!ips || ips.length === 0) return "No source IP";
  if (ips.length === 1) return ips[0];
  return `${ips.length} source IPs`;
}

function shortTrace(traceId?: string) {
  return traceId ? traceId.slice(0, 8) : "N/A";
}

async function apiFetch(path: string, projectId: string, init: RequestInit = {}) {
  const url = new URL(path, apiBase);
  if (!url.searchParams.has("projectId")) url.searchParams.set("projectId", projectId);

  return fetch(url, {
    ...init,
    headers: {
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(dashboardApiKey ? { "x-sentinel-api-key": dashboardApiKey } : {}),
      ...init.headers
    }
  });
}

function getDemoProjectData(projectId: string) {
  if (projectId === "checkout") {
    return {
      overview: checkoutOverview,
      incidents: checkoutIncidents,
      requests: checkoutRequests,
      apiKeys: checkoutApiKeys
    };
  }

  return {
    overview: demoOverview,
    incidents: demoIncidents,
    requests: demoRequests,
    apiKeys: demoApiKeys
  };
}

function createDemoApiKey(name: string): ApiKeyRecord {
  const suffix = Array.from(crypto.getRandomValues(new Uint8Array(6)))
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");

  return {
    id: `demo-key-${suffix}`,
    name,
    prefix: `sentinel_${suffix.slice(0, 8)}`,
    key: `sentinel_demo_${suffix}`,
    created_at: new Date().toISOString(),
    last_used_at: null,
    revoked_at: null
  };
}

const demoSession: AuthSession = {
  user: {
    name: "Demo Owner",
    email: "owner@sentinel.local"
  },
  organization: {
    id: "demo-org",
    name: "Demo Organization"
  },
  projects: [
    { id: "demo", name: "Demo API", role: "owner" },
    { id: "checkout", name: "Checkout API", role: "developer" }
  ]
};

const demoOverview: Overview = {
  totals: {
    events: 12842,
    openIncidents: 4,
    averageLatencyMs: 92
  },
  endpoints: [
    {
      method: "POST",
      path: "/api/login",
      requests: 2384,
      latency: 86,
      max_threat_score: 92
    },
    {
      method: "POST",
      path: "/graphql",
      requests: 1840,
      latency: 132,
      max_threat_score: 61
    },
    {
      method: "POST",
      path: "/rpc",
      requests: 956,
      latency: 74,
      max_threat_score: 76
    },
    {
      method: "GET",
      path: "/api/users/:id",
      requests: 4412,
      latency: 44,
      max_threat_score: 28
    }
  ],
  ips: [
    { ip: "203.0.113.14", requests: 942, max_threat_score: 92 },
    { ip: "198.51.100.22", requests: 518, max_threat_score: 76 },
    { ip: "192.0.2.41", requests: 304, max_threat_score: 54 },
    { ip: "198.51.100.80", requests: 88, max_threat_score: 18 }
  ]
};

const demoIncidents: Incident[] = [
  {
    id: "SC-1932",
    severity: "critical",
    title: "Potential credential stuffing on POST /api/login",
    description: "Authentication failures and single-IP request volume exceeded heuristic thresholds.",
    affected_endpoint: "POST /api/login",
    attacker_ips: ["203.0.113.14", "203.0.113.15", "203.0.113.16"],
    request_count: 35,
    status: "open",
    started_at: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
    last_seen_at: new Date().toISOString(),
    created_at: new Date().toISOString()
  },
  {
    id: "SC-1933",
    severity: "high",
    title: "Sensitive EVM RPC activity on POST /rpc",
    description: "Repeated eth_sendRawTransaction requests returned authorization failures.",
    affected_endpoint: "POST /rpc",
    attacker_ips: ["198.51.100.22"],
    request_count: 9,
    status: "open",
    started_at: new Date(Date.now() - 1000 * 60 * 12).toISOString(),
    last_seen_at: new Date(Date.now() - 1000 * 60 * 7).toISOString(),
    created_at: new Date(Date.now() - 1000 * 60 * 7).toISOString()
  }
];

const demoReadiness: Readiness = {
  status: "degraded",
  checks: {
    database: { ok: false, latencyMs: -1 },
    queue: { ok: false, latencyMs: -1, depth: -1 }
  }
};

const demoSystemMetrics: SystemMetrics = {
  uptimeSeconds: 0,
  totalRequests: 0,
  ingestionRate: 138,
  ingestionBatches: 4,
  failedJobs: 0,
  queueDepth: 0,
  databaseLatencyMs: -1,
  processingLatencyMs: 0,
  websocketConnections: 0
};

const demoRequests: RequestRecord[] = [
  {
    id: "req-1",
    trace_id: "0123456789abcdef0123456789abcdef",
    timestamp: new Date().toISOString(),
    service_name: "demo-api",
    environment: "demo",
    kind: "rest",
    method: "POST",
    path: "/api/login",
    route: "/api/login",
    ip: "203.0.113.14",
    user_agent: "curl/8.0",
    status_code: 401,
    latency_ms: 82,
    auth_present: true,
    auth_failed: true,
    threat_score: 92,
    threat_severity: "critical"
  },
  {
    id: "req-2",
    trace_id: "1123456789abcdef0123456789abcdef",
    timestamp: new Date(Date.now() - 1000 * 45).toISOString(),
    service_name: "demo-api",
    environment: "demo",
    kind: "evm_rpc",
    method: "POST",
    path: "/rpc",
    route: "/rpc",
    ip: "198.51.100.22",
    status_code: 401,
    latency_ms: 76,
    auth_present: true,
    auth_failed: true,
    evm_rpc_method: "eth_sendRawTransaction",
    threat_score: 76,
    threat_severity: "high"
  },
  {
    id: "req-3",
    trace_id: "2123456789abcdef0123456789abcdef",
    timestamp: new Date(Date.now() - 1000 * 90).toISOString(),
    service_name: "demo-api",
    environment: "demo",
    kind: "graphql",
    method: "POST",
    path: "/graphql",
    route: "/graphql",
    ip: "192.0.2.41",
    status_code: 500,
    latency_ms: 184,
    auth_present: true,
    auth_failed: false,
    graphql_operation_name: "UpdateProfile",
    graphql_operation_type: "mutation",
    threat_score: 61,
    threat_severity: "high"
  },
  {
    id: "req-4",
    trace_id: "3123456789abcdef0123456789abcdef",
    timestamp: new Date(Date.now() - 1000 * 120).toISOString(),
    service_name: "demo-api",
    environment: "demo",
    kind: "rest",
    method: "GET",
    path: "/api/users/283",
    route: "/api/users/:id",
    ip: "198.51.100.80",
    status_code: 200,
    latency_ms: 44,
    auth_present: true,
    auth_failed: false,
    threat_score: 18,
    threat_severity: "low"
  }
];

const demoApiKeys: ApiKeyRecord[] = [
  {
    id: "demo-key-primary",
    name: "Production SDK",
    prefix: "sentinel_prod",
    created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 4).toISOString(),
    last_used_at: new Date(Date.now() - 1000 * 60 * 11).toISOString(),
    revoked_at: null
  },
  {
    id: "demo-key-ci",
    name: "CI Smoke Tests",
    prefix: "sentinel_ci",
    created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 18).toISOString(),
    last_used_at: null,
    revoked_at: null
  }
];

const checkoutOverview: Overview = {
  totals: {
    events: 6421,
    openIncidents: 2,
    averageLatencyMs: 118
  },
  endpoints: [
    {
      method: "POST",
      path: "/api/checkout",
      requests: 1704,
      latency: 124,
      max_threat_score: 68
    },
    {
      method: "POST",
      path: "/api/payment-intents",
      requests: 1388,
      latency: 142,
      max_threat_score: 73
    },
    {
      method: "GET",
      path: "/api/orders/:id",
      requests: 2384,
      latency: 52,
      max_threat_score: 34
    }
  ],
  ips: [
    { ip: "203.0.113.88", requests: 402, max_threat_score: 73 },
    { ip: "198.51.100.44", requests: 318, max_threat_score: 68 },
    { ip: "192.0.2.18", requests: 121, max_threat_score: 24 }
  ]
};

const checkoutIncidents: Incident[] = [
  {
    id: "SC-2210",
    severity: "high",
    title: "Payment authorization failures on POST /api/payment-intents",
    description: "A concentrated source triggered repeated payment failures within a short window.",
    affected_endpoint: "POST /api/payment-intents",
    attacker_ips: ["203.0.113.88"],
    request_count: 18,
    status: "open",
    started_at: new Date(Date.now() - 1000 * 60 * 16).toISOString(),
    last_seen_at: new Date(Date.now() - 1000 * 60 * 3).toISOString(),
    created_at: new Date(Date.now() - 1000 * 60 * 12).toISOString()
  }
];

const checkoutRequests: RequestRecord[] = [
  {
    id: "checkout-1",
    trace_id: "4123456789abcdef0123456789abcdef",
    timestamp: new Date().toISOString(),
    service_name: "checkout-api",
    environment: "demo",
    kind: "rest",
    method: "POST",
    path: "/api/payment-intents",
    route: "/api/payment-intents",
    ip: "203.0.113.88",
    status_code: 402,
    latency_ms: 142,
    auth_present: true,
    auth_failed: false,
    threat_score: 73,
    threat_severity: "high"
  },
  {
    id: "checkout-2",
    trace_id: "5123456789abcdef0123456789abcdef",
    timestamp: new Date(Date.now() - 1000 * 36).toISOString(),
    service_name: "checkout-api",
    environment: "demo",
    kind: "rest",
    method: "POST",
    path: "/api/checkout",
    route: "/api/checkout",
    ip: "198.51.100.44",
    status_code: 429,
    latency_ms: 118,
    auth_present: true,
    auth_failed: false,
    threat_score: 68,
    threat_severity: "high"
  }
];

const checkoutApiKeys: ApiKeyRecord[] = [
  {
    id: "checkout-key-web",
    name: "Checkout API SDK",
    prefix: "sentinel_pay",
    created_at: new Date(Date.now() - 1000 * 60 * 60 * 24 * 6).toISOString(),
    last_used_at: new Date(Date.now() - 1000 * 60 * 27).toISOString(),
    revoked_at: null
  }
];

function filterDemoRequests(requests: RequestRecord[], filters: RequestFilters) {
  return requests.filter((request) => {
    if (filters.method && request.method !== filters.method) return false;
    if (filters.status && request.status_code !== Number(filters.status)) return false;
    if (filters.ip && request.ip !== filters.ip) return false;
    if (filters.threatMin && request.threat_score < Number(filters.threatMin)) return false;
    if (filters.query) {
      const haystack = `${request.path} ${request.route ?? ""}`.toLowerCase();
      return haystack.includes(filters.query.toLowerCase());
    }
    return true;
  });
}
