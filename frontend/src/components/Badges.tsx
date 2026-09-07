export function SeverityBadge({ severity }: { severity: string }) {
  const s = (severity || "none").toLowerCase();
  const label = s === "none" ? "benign" : s;
  return <span className={`badge sev-${s}`}>{label}</span>;
}

export function ClassBadge({ label }: { label: string }) {
  return <span className="badge class-badge">{label}</span>;
}

export function ActionBadge({ action }: { action: string }) {
  const a = (action || "ALLOW").toUpperCase();
  return <span className={`badge action-${a === "BLOCK" ? "block" : "allow"}`}>{a}</span>;
}
