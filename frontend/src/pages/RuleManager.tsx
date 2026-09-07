import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";
import { SeverityBadge } from "../components/Badges";

export function RuleManager() {
  const [rules, setRules] = useState<any[]>([]);
  const [error, setError] = useState<string | null>(null);

  function load() {
    api.rules().then((r) => setRules(r.rules)).catch((e) => setError(String(e)));
  }
  useEffect(load, []);

  return (
    <Layout
      title="Signature Rules"
      subtitle="OWASP-CRS-style regex rules, matched independently of the ML classifier against decoded request content. Edit backend/app/detection/rules.yaml and reload."
    >
      {error && <div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>{error}</div>}
      <div className="panel">
        <div className="panel-header">
          <h3>{rules.length} active rule(s)</h3>
          <button className="btn" onClick={load}>Refresh</button>
        </div>
        <div className="panel-body">
          {rules.map((r) => (
            <div key={r.id} className="panel" style={{ marginBottom: 12 }}>
              <div className="panel-header">
                <h3><span className="mono">{r.id}</span> &mdash; {r.name}</h3>
                <SeverityBadge severity={r.severity} />
              </div>
              <div className="panel-body">
                <p style={{ margin: "0 0 10px 0", fontSize: 13 }}>{r.description}</p>
                <table className="data-table">
                  <thead><tr><th>Field</th><th>Pattern</th></tr></thead>
                  <tbody>
                    <tr>
                      <td className="mono">{r.field}</td>
                      <td className="mono" style={{ wordBreak: "break-all" }}>{r.pattern}</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
}
