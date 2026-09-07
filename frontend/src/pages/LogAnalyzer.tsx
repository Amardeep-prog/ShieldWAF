import { useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";
import { SeverityBadge, ClassBadge, ActionBadge } from "../components/Badges";

export function LogAnalyzer() {
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  async function onUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const res = await api.uploadLog(file);
      setResult(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setBusy(false);
      e.target.value = "";
    }
  }

  return (
    <Layout
      title="Log Analyzer"
      subtitle="Upload an Apache/Nginx access.log (Combined Log Format). Every historical request line is re-run through the exact same detection engine that inspects live proxied traffic -- useful for auditing whether attacks already got through before ShieldWAF was deployed."
    >
      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header"><h3>Upload access log</h3></div>
        <div className="panel-body">
          <p className="note-box">
            Expected format: <code className="inline">
              127.0.0.1 - - [10/Oct/2023:13:55:36 -0700] "GET / HTTP/1.1" 200 100 "-" "Mozilla/5.0"
            </code>. Max 10&nbsp;MB / 20,000 lines for this demo deployment.
          </p>
          <input type="file" accept=".log,.txt" onChange={onUpload} disabled={busy} />
          {busy && <p style={{ marginTop: 10, color: "#5b6b82" }}>Parsing and inspecting...</p>}
        </div>
      </div>

      {error && <div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>{error}</div>}

      {result && (
        <>
          <div className="stat-grid">
            <div className="stat-tile">
              <div className="stat-label">LINES PARSED</div>
              <div className="stat-value">{result.lines_parsed}</div>
            </div>
            <div className="stat-tile">
              <div className="stat-label">LINES FAILED TO PARSE</div>
              <div className="stat-value">{result.lines_failed}</div>
            </div>
            <div className="stat-tile tone-critical">
              <div className="stat-label">WOULD HAVE BEEN BLOCKED</div>
              <div className="stat-value">
                {result.results.filter((r: any) => r.action === "BLOCK").length}
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h3>Batch {result.batch_id} &mdash; parsed requests</h3>
              <button className="btn" onClick={() => window.open(api.reportUrl(result.batch_id), "_blank")}>
                Download PDF report
              </button>
            </div>
            <div className="panel-body" style={{ overflowX: "auto" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Client IP</th><th>Path</th><th>Predicted</th><th>Confidence</th>
                    <th>Rule matches</th><th>Severity</th><th>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {result.results.map((r: any, i: number) => (
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
        </>
      )}
    </Layout>
  );
}
