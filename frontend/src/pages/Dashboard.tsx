import { useEffect, useState } from "react";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";

const SEV_COLORS: Record<string, string> = {
  critical: "#b91c1c",
  high: "#b45309",
  medium: "#92720c",
  low: "#1d5c8a",
  none: "#15803d",
};

export function Dashboard() {
  const [stats, setStats] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.dashboardStats().then(setStats).catch((e) => setError(String(e)));
  }, []);

  const byClass = stats?.by_class || {};
  const bySeverity = stats?.by_severity || {};
  const classData = Object.entries(byClass).map(([k, v]) => ({ name: k, count: v as number }));
  const sevData = Object.entries(bySeverity).map(([k, v]) => ({ name: k, value: v as number }));
  const topAttackers = stats?.top_attacker_ips || [];

  return (
    <Layout
      title="Dashboard"
      subtitle="Overview of everything ShieldWAF has inspected -- run a batch from Request Inspector, upload an access log, or send live traffic through the reverse proxy."
    >
      {error && (
        <div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>
          Could not reach the backend API ({error}). Start it with{" "}
          <code className="inline">uvicorn app.main:app --reload</code> from the{" "}
          <code className="inline">backend/</code> directory.
        </div>
      )}

      <div className="stat-grid">
        <div className="stat-tile">
          <div className="stat-label">TOTAL REQUESTS INSPECTED</div>
          <div className="stat-value">{stats?.total_requests ?? "--"}</div>
        </div>
        <div className="stat-tile">
          <div className="stat-label">BATCHES PROCESSED</div>
          <div className="stat-value">{stats?.total_batches ?? "--"}</div>
        </div>
        <div className="stat-tile tone-critical">
          <div className="stat-label">BLOCKED REQUESTS</div>
          <div className="stat-value">{stats?.blocked_requests ?? "--"}</div>
        </div>
        <div className="stat-tile tone-high">
          <div className="stat-label">DISTINCT ATTACKER IPs</div>
          <div className="stat-value">{topAttackers.length}</div>
        </div>
      </div>

      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="panel">
          <div className="panel-header"><h3>Requests by Predicted Class</h3></div>
          <div className="panel-body">
            {classData.length ? (
              <ResponsiveContainer width="100%" height={260}>
                <BarChart data={classData} layout="vertical" margin={{ left: 20 }}>
                  <XAxis type="number" allowDecimals={false} />
                  <YAxis type="category" dataKey="name" width={110} fontSize={11} />
                  <Tooltip />
                  <Bar dataKey="count" fill="#7a3b12" radius={[0, 2, 2, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state">No requests inspected yet.</div>
            )}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h3>Alerts by Severity</h3></div>
          <div className="panel-body">
            {sevData.length ? (
              <ResponsiveContainer width="100%" height={260}>
                <PieChart>
                  <Pie data={sevData} dataKey="value" nameKey="name" innerRadius={55} outerRadius={90}>
                    {sevData.map((entry, i) => (
                      <Cell key={i} fill={SEV_COLORS[entry.name] || "#94a3b8"} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="empty-state">No severity-tagged alerts yet.</div>
            )}
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header"><h3>Top attacker IPs (by blocked requests)</h3></div>
        <div className="panel-body">
          {topAttackers.length ? (
            <table className="data-table">
              <thead><tr><th>IP</th><th>Blocked requests</th></tr></thead>
              <tbody>
                {topAttackers.map((a: any) => (
                  <tr key={a.ip}><td className="mono">{a.ip}</td><td className="mono">{a.count}</td></tr>
                ))}
              </tbody>
            </table>
          ) : (
            <div className="empty-state">No blocked requests recorded yet.</div>
          )}
        </div>
      </div>
    </Layout>
  );
}
