import { useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";
import { SeverityBadge, ClassBadge, ActionBadge } from "../components/Badges";
import { CLASSES } from "../lib/constants";

export function RequestInspector() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [sampleClass, setSampleClass] = useState("SQLI");
  const [sampleN, setSampleN] = useState(5);

  const [method, setMethod] = useState("GET");
  const [path, setPath] = useState("/search");
  const [query, setQuery] = useState("q=1' UNION SELECT username,password FROM users--");
  const [body, setBody] = useState("");

  async function runSample() {
    setBusy(true);
    setError(null);
    try {
      const { requests } = await api.sample(sampleClass, sampleN);
      const classified = await api.inspect(requests);
      setResult(classified);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function runManual() {
    setBusy(true);
    setError(null);
    try {
      const classified = await api.inspect([
        { method, path, query_string: query, body, headers: { "User-Agent": "Mozilla/5.0" }, client_ip: "203.0.113.50" },
      ]);
      setResult(classified);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  function downloadReport() {
    if (!result?.batch_id) return;
    window.open(api.reportUrl(result.batch_id), "_blank");
  }

  return (
    <Layout
      title="Request Inspector"
      subtitle="Test a single crafted HTTP request against the hybrid ML + signature engine, or generate demo requests for a known attack class."
    >
      <div className="two-col" style={{ marginBottom: 20 }}>
        <div className="panel">
          <div className="panel-header"><h3>Craft a request manually</h3></div>
          <div className="panel-body">
            <div style={{ display: "flex", gap: 10, marginBottom: 10 }}>
              <div>
                <label className="field-label">Method</label>
                <select value={method} onChange={(e) => setMethod(e.target.value)}>
                  <option>GET</option><option>POST</option><option>PUT</option>
                </select>
              </div>
              <div style={{ flex: 1 }}>
                <label className="field-label">Path</label>
                <input type="text" value={path} onChange={(e) => setPath(e.target.value)} style={{ width: "100%" }} />
              </div>
            </div>
            <label className="field-label">Query string</label>
            <input type="text" value={query} onChange={(e) => setQuery(e.target.value)} style={{ width: "100%", marginBottom: 10 }} />
            <label className="field-label">Body</label>
            <textarea value={body} onChange={(e) => setBody(e.target.value)} rows={3} style={{ width: "100%", marginBottom: 10 }} />
            <button className="btn primary" onClick={runManual} disabled={busy}>
              {busy ? "Inspecting..." : "Inspect this request"}
            </button>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header"><h3>Generate demo requests</h3></div>
          <div className="panel-body">
            <p className="note-box">
              Generates requests built from real, documented OWASP-style payload
              strings for the selected class (see backend <code className="inline">dataset.py</code>).
            </p>
            <div style={{ display: "flex", gap: 10, alignItems: "flex-end" }}>
              <div>
                <label className="field-label">Attack class</label>
                <select value={sampleClass} onChange={(e) => setSampleClass(e.target.value)}>
                  {CLASSES.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </div>
              <div>
                <label className="field-label">Count</label>
                <input type="number" min={1} max={30} value={sampleN}
                  onChange={(e) => setSampleN(Number(e.target.value))} style={{ width: 70 }} />
              </div>
              <button className="btn primary" onClick={runSample} disabled={busy}>
                {busy ? "Inspecting..." : "Generate & inspect"}
              </button>
            </div>
          </div>
        </div>
      </div>

      {error && <div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>{error}</div>}

      {result && (
        <div className="panel">
          <div className="panel-header">
            <h3>Batch {result.batch_id} &mdash; {result.results?.length ?? 0} request(s)</h3>
            <button className="btn" onClick={downloadReport}>Download PDF report</button>
          </div>
          <div className="panel-body" style={{ overflowX: "auto" }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Client IP</th><th>Path</th><th>Predicted</th><th>Confidence</th>
                  <th>Rule matches</th><th>Severity</th><th>Action</th>
                </tr>
              </thead>
              <tbody>
                {result.results?.map((r: any, i: number) => (
                  <tr key={i}>
                    <td className="mono">{r.client_ip}</td>
                    <td className="mono">{r.path}{r.query_string ? `?${r.query_string}` : ""}</td>
                    <td><ClassBadge label={r.predicted_class} /></td>
                    <td className="mono">{(r.confidence * 100).toFixed(1)}%</td>
                    <td>{r.rule_matches?.length ? r.rule_matches.map((m: any) => m.name).join(", ") : "--"}</td>
                    <td><SeverityBadge severity={r.severity} /></td>
                    <td><ActionBadge action={r.action} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </Layout>
  );
}
