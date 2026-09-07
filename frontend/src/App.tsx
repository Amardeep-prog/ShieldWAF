import { useState } from "react";
import { Sidebar, PageKey } from "./components/Sidebar";
import { Dashboard } from "./pages/Dashboard";
import { RequestInspector } from "./pages/RequestInspector";
import { LogAnalyzer } from "./pages/LogAnalyzer";
import { LiveTraffic } from "./pages/LiveTraffic";
import { RuleManager } from "./pages/RuleManager";
import { Blocklist } from "./pages/Blocklist";
import { ModelPerformance } from "./pages/ModelPerformance";

export default function App() {
  const [page, setPage] = useState<PageKey>("dashboard");

  return (
    <div className="app-shell">
      <Sidebar active={page} onNavigate={setPage} />
      {page === "dashboard" && <Dashboard />}
      {page === "inspector" && <RequestInspector />}
      {page === "logs" && <LogAnalyzer />}
      {page === "live" && <LiveTraffic />}
      {page === "rules" && <RuleManager />}
      {page === "blocklist" && <Blocklist />}
      {page === "model" && <ModelPerformance />}
    </div>
  );
}
