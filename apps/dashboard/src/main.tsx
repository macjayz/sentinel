import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  AlertTriangle,
  Clock,
  Database,
  Gauge,
  Globe2,
  Radio,
  ShieldCheck
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
  severity: string;
  title: string;
  description: string;
  status: string;
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

const apiBase = import.meta.env.VITE_SENTINEL_API_URL ?? "http://localhost:8080";

function App() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [readiness, setReadiness] = useState<Readiness>(demoReadiness);
  const [systemMetrics, setSystemMetrics] = useState<SystemMetrics>(demoSystemMetrics);
  const [liveStatus, setLiveStatus] = useState("Connecting");

  useEffect(() => {
    async function load() {
      try {
        const [overviewResponse, incidentResponse, readinessResponse, systemResponse] = await Promise.all([
          fetch(`${apiBase}/v1/analytics/overview`),
          fetch(`${apiBase}/v1/analytics/incidents`),
          fetch(`${apiBase}/ready`),
          fetch(`${apiBase}/v1/analytics/system`)
        ]);

        if (
          !overviewResponse.ok ||
          !incidentResponse.ok ||
          !readinessResponse.ok ||
          !systemResponse.ok
        ) {
          throw new Error("analytics_unavailable");
        }

        setOverview(await overviewResponse.json());
        setIncidents(await incidentResponse.json());
        setReadiness(await readinessResponse.json());
        setSystemMetrics(await systemResponse.json());
      } catch {
        setOverview(demoOverview);
        setIncidents(demoIncidents);
        setReadiness(demoReadiness);
        setSystemMetrics(demoSystemMetrics);
      }
    }

    void load();
    const interval = window.setInterval(() => void load(), 15000);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    const liveUrl = apiBase.replace(/^http/, "ws") + "/live";
    const socket = new WebSocket(liveUrl);

    socket.addEventListener("open", () => setLiveStatus("Live"));
    socket.addEventListener("close", () => setLiveStatus("Offline"));
    socket.addEventListener("message", () => setLiveStatus("Event received"));

    return () => socket.close();
  }, []);

  const maxThreatScore = useMemo(() => {
    const endpointScores = overview?.endpoints.map((endpoint) => endpoint.max_threat_score) ?? [];
    const ipScores = overview?.ips.map((ip) => ip.max_threat_score) ?? [];
    return Math.max(0, ...endpointScores, ...ipScores);
  }, [overview]);

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
          <a className="active">Overview</a>
          <a>Endpoints</a>
          <a>Incidents</a>
          <a>Sources</a>
        </nav>
      </aside>

      <section className="workspace">
        <header className="topbar">
          <div>
            <h1>Security Overview</h1>
            <p>REST, GraphQL, and EVM JSON-RPC telemetry from monitored services.</p>
          </div>
          <div className={`live-pill ${liveStatus.toLowerCase().replace(/\s+/g, "-")}`}>
            <Radio size={16} />
            {liveStatus}
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

        <Panel title="Incidents">
          <div className="incident-list">
            {incidents.map((incident) => (
              <article className="incident" key={incident.id}>
                <span className={`severity ${incident.severity}`}>{incident.severity}</span>
                <div>
                  <strong>{incident.title}</strong>
                  <p>{incident.description}</p>
                </div>
                <time>{new Date(incident.created_at).toLocaleString()}</time>
              </article>
            ))}
          </div>
        </Panel>
      </section>
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
    status: "open",
    created_at: new Date().toISOString()
  },
  {
    id: "SC-1933",
    severity: "high",
    title: "Sensitive EVM RPC activity on POST /rpc",
    description: "Repeated eth_sendRawTransaction requests returned authorization failures.",
    status: "open",
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
