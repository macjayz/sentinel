import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, AlertTriangle, Clock, Globe2, Radio, ShieldCheck } from "lucide-react";
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

const apiBase = import.meta.env.VITE_SENTINEL_API_URL ?? "http://localhost:8080";

function App() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [liveStatus, setLiveStatus] = useState("Connecting");

  useEffect(() => {
    async function load() {
      const [overviewResponse, incidentResponse] = await Promise.all([
        fetch(`${apiBase}/v1/analytics/overview`),
        fetch(`${apiBase}/v1/analytics/incidents`)
      ]);

      setOverview(await overviewResponse.json());
      setIncidents(await incidentResponse.json());
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
          <div className="live-pill">
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

createRoot(document.getElementById("root")!).render(<App />);
