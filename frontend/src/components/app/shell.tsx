import { Link, useRouterState } from "@tanstack/react-router";
import { Activity, ArrowUpRight, ChartNoAxesCombined, ChevronDown, Database, Download, FileUp, LayoutDashboard, Menu, PanelLeftClose, Search, Shield, Workflow, X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { Button } from "@/components/ui/button";

const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard },
  { to: "/upload", label: "Log Upload", icon: FileUp },
  { to: "/processing", label: "Processing", icon: Workflow },
  { to: "/explorer", label: "Log Explorer", icon: Search },
  { to: "/analytics", label: "Analytics", icon: ChartNoAxesCombined },
  { to: "/export", label: "Export Center", icon: Download },
] as const;

export function AppShell({ children }: { children: ReactNode }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const path = useRouterState({ select: (s) => s.location.pathname });
  const active = navigation.find((item) => item.to === path)?.label ?? "Dashboard";
  return <div className="app-frame">
    {mobileOpen && <div className="mobile-scrim" onClick={() => setMobileOpen(false)} />}
    <aside className={`sidebar ${mobileOpen ? "sidebar-open" : ""}`}>
      <div className="brand-block">
        <div className="brand-mark"><span /><span /><span /></div>
        <div><div className="brand-name">AKATSUKI<span className="brand-period">.</span></div><div className="brand-caption">UNIVERSAL LOG FRAMEWORK</div></div>
        <Button variant="ghost" size="icon" className="mobile-close" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X /></Button>
      </div>
      <div className="sidebar-divider" />
      <div className="nav-label">WORKSPACE</div>
      <nav className="sidebar-nav" aria-label="Main navigation">
        {navigation.map(({ to, label, icon: Icon }) => <Link key={to} to={to} onClick={() => setMobileOpen(false)} className={`nav-link ${path === to ? "nav-active" : ""}`}><Icon size={18} strokeWidth={1.8} /><span>{label}</span>{path === to && <span className="nav-indicator" />}</Link>)}
      </nav>
      <div className="sidebar-spacer" />
      <div className="sidebar-context"><div className="context-heading"><Activity size={15} /> SYSTEM STATUS</div><div className="context-row"><span className="status-dot" /> All systems operational</div><div className="context-small">Last sync: just now</div></div>
      <div className="sidebar-profile"><div className="avatar">SA</div><div><strong>Security Analyst</strong><small>Administrator</small></div><ChevronDown size={15} /></div>
    </aside>
    <div className="main-column">
      <header className="topbar"><div className="topbar-left"><Button variant="ghost" size="icon" className="mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu /></Button><span className="breadcrumb-parent">Workspace</span><span className="breadcrumb-slash">/</span><span className="breadcrumb-current">{active}</span></div><div className="topbar-right"><span className="topbar-project">SIH 2026 <span className="topbar-separator">/</span> SIH26156</span><div className="topbar-line" /><span className="live-indicator"><span className="status-dot" /> ENGINE ONLINE</span></div></header>
      <main className="page-content">{children}</main>
      <footer className="app-footer"><span>© 2026 AKATSUKI <span className="footer-separator">/</span> UNIVERSAL LOG PRE-PROCESSING FRAMEWORK</span><span>BUILT FOR SMART INDIA HACKATHON <ArrowUpRight size={13} /></span></footer>
    </div>
  </div>;
}

export function PageHeader({ eyebrow, title, description, action }: { eyebrow: string; title: string; description: string; action?: ReactNode }) {
  return <div className="page-heading"><div><div className="eyebrow"><span className="eyebrow-line" />{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>{action && <div className="page-heading-action">{action}</div>}</div>;
}
export function SectionHeading({ title, subtitle, action }: { title: string; subtitle?: string; action?: ReactNode }) {
  return <div className="section-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>;
}
export function SeverityBadge({ severity }: { severity: string }) { return <span className={`severity-badge severity-${severity.toLowerCase()}`}><span className="badge-dot" />{severity}</span>; }
export function StatusBadge({ status }: { status: string }) { return <span className={`status-badge status-${status.toLowerCase()}`}>{status}</span>; }
export function PanelLeftIcon() { return <PanelLeftClose size={18} />; }
export function DatabaseIcon() { return <Database size={18} />; }
export function ShieldIcon() { return <Shield size={18} />; }
