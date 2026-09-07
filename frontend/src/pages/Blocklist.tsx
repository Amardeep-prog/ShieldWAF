import { useEffect, useState } from "react";
import { Layout } from "../components/Layout";
import { api } from "../lib/api";

export function Blocklist() {
  const [blocked, setBlocked] = useState<Record<string, any>>({});
  const [error, setError] = useState<string | null>(null);
  const [ip, setIp] = useState("");
  const [reason, setReason] = useState("manually blocked by analyst");

  function load() {
    api.blocklist().then((r) => setBlocked(r.blocked_ips)).catch((e) => setError(String(e)));
  }
  useEffect(load, []);

  async function doBlock() {
    if (!ip.trim()) return;
    await api.blockIp(ip.trim(), reason);
    setIp("");
    load();
  }

  async function doUnblock(target: string) {
    await api.unblockIp(target);
    load();
  }

  const entries = Object.entries(blocked);

  return (
    <Layout
      title="IP Blocklist"
      subtitle="ShieldWAF's in-process rate limiter and repeat-offender auto-block. An IP lands here automatically after exceeding the request-rate limit or after 3 malicious verdicts within a rolling window, or you can block one manually."
    >
      {error && <div className="note-box" style={{ borderLeftColor: "#b91c1c" }}>{error}</div>}

      <div className="panel" style={{ marginBottom: 20 }}>
        <div className="panel-header"><h3>Manually block an IP</h3></div>
        <div className="panel-body">
          <div style={{ display: "flex", gap: 10 }}>
            <input type="text" placeholder="e.g. 203.0.113.9" value={ip}
              onChange={(e) => setIp(e.target.value)} style={{ flex: 1 }} />
            <input type="text" placeholder="reason" value={reason}
              onChange={(e) => setReason(e.target.value)} style={{ flex: 1 }} />
            <button className="btn primary" onClick={doBlock}>Block</button>
          </div>
        </div>
      </div>

      <div className="panel">
        <div className="panel-header">
          <h3>{entries.length} IP(s) currently blocked</h3>
          <button className="btn" onClick={load}>Refresh</button>
        </div>
        <div className="panel-body">
          {entries.length === 0 ? (
            <div className="empty-state">No IPs currently blocked.</div>
          ) : (
            <table className="data-table">
              <thead><tr><th>IP</th><th>Reason</th><th>Remaining</th><th></th></tr></thead>
              <tbody>
                {entries.map(([addr, info]) => (
                  <tr key={addr}>
                    <td className="mono">{addr}</td>
                    <td>{info.reason}</td>
                    <td className="mono">{Math.round(info.remaining_seconds)}s</td>
                    <td><button className="btn" onClick={() => doUnblock(addr)}>Unblock</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </Layout>
  );
}
