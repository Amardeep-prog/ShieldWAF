import React, { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";
import { SeverityBadge, ClassBadge } from "../components/Badges";

export function LiveTraffic() {
  const [alerts, setAlerts] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [explaining, setExplaining] = useState<number | null>(null);
  const [explanations, setExplanations] = useState<Record<number, string>>({});

  function load() {
    api.alerts(200).then((r) => setAlerts(r.alerts)).catch((e) => setError(String(e)));
  }
  useEffect(load, []);

  async function explain(id: number) {
    setExplaining(id);
    try {
      const res = await api.explainRequest(id);
      setExplanations((prev) => ({ ...prev, [id]: res.explanation }));
    } catch (e) {
      setExplanations((prev) => ({ ...prev, [id]: `Could not generate explanation: ${e}` }));
    } finally {
      setExplaining(null);
    }
  }

  async function feedback(id: number, verdict: "true_positive" | "false_positive") {
    await api.submitFeedback(id, verdict);
    load();
  }

  async function block(ip: string) {
    await api.blockIp(ip);
    const advisory = await api.firewallAdvisory(ip);
    alert(
      `${ip} has been blocked in ShieldWAF's in-process blocklist.\n\n` +
      `For defence-in-depth at the network edge too:\n\n` +
      `iptables: ${advisory.iptables_cmd}\nufw: ${advisory.ufw_cmd}\nnginx: ${advisory.nginx_deny_snippet}`
    );
  }

  return (
    <Layout
      title="Live Traffic"
      subtitle="Requests blocked by the reverse proxy in real time (mount ShieldWAF in front of a real upstream app -- see README -- to populate this with genuine live traffic, not just test batches)."
    >
      {error && <div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>{error}</div>}
      <div className="panel">
        <div className="panel-header">
          <h3>{alerts.length} blocked request(s)</h3>
          <button className="btn" onClick={load}>Refresh</button>
        </div>
        <div className="panel-body" style={{ overflowX: "auto" }}>
          {alerts.length === 0 ? (
            <div className="empty-state">
              No blocked requests yet. Run the reverse proxy in front of an app
              (or use Request Inspector / Log Analyzer) to populate this.
            </div>
          ) : (
            <table className="data-table">
              <thead>
                <tr>
                  <th>ID</th><th>Client IP</th><th>Path</th><th>Class</th>
                  <th>Confidence</th><th>Severity</th><th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map((a) => (
                  <React.Fragment key={a.id}>
                    <tr>
                      <td className="mono">{a.id}</td>
                      <td className="mono">{a.client_ip || "--"}</td>
                      <td className="mono">{a.path}{a.query_string ? `?${a.query_string}` : ""}</td>
                      <td><ClassBadge label={a.predicted_class} /></td>
                      <td className="mono">{(a.confidence * 100).toFixed(1)}%</td>
                      <td><SeverityBadge severity={a.severity} /></td>
                      <td>
                        <div className="pill-row">
                          <button className="btn" onClick={() => explain(a.id)} disabled={explaining === a.id}>
                            {explaining === a.id ? "..." : "AI explain"}
                          </button>
                          <button className="btn" onClick={() => feedback(a.id, "true_positive")}>TP</button>
                          <button className="btn" onClick={() => feedback(a.id, "false_positive")}>FP</button>
                          {a.client_ip && (
                            <button className="btn" onClick={() => block(a.client_ip)}>Block IP</button>
                          )}
                        </div>
                      </td>
                    </tr>
                    {explanations[a.id] && (
                      <tr>
                        <td colSpan={7}><div className="note-box">{explanations[a.id]}</div></td>
                      </tr>
                    )}
                  </React.Fragment>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Layout>
  );
}
