import {
  ShieldHalf,
  LayoutDashboard,
  TerminalSquare,
  FileSearch,
  Activity,
  ShieldAlert,
  Ban,
  BarChart3,
} from "lucide-react";

export type PageKey =
  | "dashboard"
  | "inspector"
  | "logs"
  | "live"
  | "rules"
  | "blocklist"
  | "model";

const NAV: { key: PageKey; label: string; icon: React.ReactNode }[] = [
  { key: "dashboard", label: "Dashboard", icon: <LayoutDashboard size={16} /> },
  { key: "inspector", label: "Request Inspector", icon: <TerminalSquare size={16} /> },
  { key: "logs", label: "Log Analyzer", icon: <FileSearch size={16} /> },
  { key: "live", label: "Live Traffic", icon: <Activity size={16} /> },
  { key: "rules", label: "Signature Rules", icon: <ShieldAlert size={16} /> },
  { key: "blocklist", label: "IP Blocklist", icon: <Ban size={16} /> },
  { key: "model", label: "Model Performance", icon: <BarChart3 size={16} /> },
];

export function Sidebar({
  active,
  onNavigate,
}: {
  active: PageKey;
  onNavigate: (k: PageKey) => void;
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="sidebar-brand-mark">
          <ShieldHalf size={18} />
        </div>
        <div className="sidebar-brand-text">
          <strong>ShieldWAF</strong>
          <span>ML + Signature WAF Console</span>
        </div>
      </div>
      <nav className="sidebar-nav">
        {NAV.map((item) => (
          <button
            key={item.key}
            className={`sidebar-link ${active === item.key ? "active" : ""}`}
            onClick={() => onNavigate(item.key)}
          >
            {item.icon}
            {item.label}
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        M.Tech Final Year Project
        <br />
        ML + Regex + Reverse Proxy
      </div>
    </aside>
  );
}
