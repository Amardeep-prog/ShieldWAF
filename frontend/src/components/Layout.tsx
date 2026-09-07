import { ReactNode } from "react";

export function Layout({
  title,
  subtitle,
  children,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
}) {
  return (
    <div className="main-col">
      <div className="topbar">
        <div className="topbar-title">{title}</div>
        <div className="topbar-status">
          <span className="status-dot" />
          Backend connected
        </div>
      </div>
      <div className="content">
        {subtitle && <p className="section-subtitle">{subtitle}</p>}
        {children}
      </div>
    </div>
  );
}
