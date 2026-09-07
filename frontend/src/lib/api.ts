const BASE = "/api";

async function req<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json();
}

export const api = {
  health: () => req<any>("/health"),
  dashboardStats: () => req<any>("/dashboard/stats"),
  alerts: (limit = 100) => req<any>(`/alerts?limit=${limit}`),

  inspectSchema: () => req<any>("/inspect/schema"),
  inspect: (requests: any[]) =>
    req<any>("/inspect", { method: "POST", body: JSON.stringify({ requests }) }),
  inspectHistory: (limit = 50) => req<any>(`/inspect/history?limit=${limit}`),
  getBatch: (batchId: string) => req<any>(`/inspect/${batchId}`),
  sample: (label: string, n = 5) => req<any>(`/inspect/sample/${label}?n=${n}`),

  uploadLog: async (file: File) => {
    const fd = new FormData();
    fd.append("file", file);
    const res = await fetch(`${BASE}/logs/upload`, { method: "POST", body: fd });
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  },

  modelMetrics: () => req<any>("/model/metrics"),
  retrain: () => req<any>("/model/retrain", { method: "POST" }),

  rules: () => req<any>("/rules"),

  blocklist: () => req<any>("/blocklist"),
  blockIp: (ip: string, reason = "manually blocked by analyst") =>
    req<any>("/blocklist/block", { method: "POST", body: JSON.stringify({ ip, reason }) }),
  unblockIp: (ip: string) => req<any>(`/blocklist/unblock/${ip}`, { method: "POST" }),

  firewallAdvisory: (ip: string) => req<any>(`/firewall/advisory/${ip}`),

  explainRequest: (request_id: number) =>
    req<any>("/ai/explain", { method: "POST", body: JSON.stringify({ request_id }) }),

  submitFeedback: (request_id: number, verdict: string, note = "") =>
    req<any>("/feedback", {
      method: "POST",
      body: JSON.stringify({ request_id, verdict, note }),
    }),

  reportUrl: (batchId: string) => `${BASE}/reports/${batchId}`,
};
