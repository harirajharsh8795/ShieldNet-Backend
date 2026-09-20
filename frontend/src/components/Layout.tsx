import { useState, type ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { BarChart3, Eye, Menu, Shield, X, Download, ShieldCheck } from "lucide-react";
import { OfflineStatusBadge } from "./OfflineStatusBadge";
import { ThemeToggle } from "./ThemeToggle";
import { Sparkle3DBackground } from "./Sparkle3DBackground";
import { AuthBar } from "./AuthBar";
import { DownloadAgentModal } from "./DownloadAgentModal";

interface NavItem {
  to: string;
  label: string;
  icon?: any;
  end?: boolean;
}

const NAV_ITEMS: NavItem[] = [
  { to: "/", label: "Home", end: true },
  { to: "/about", label: "About", end: false },
  { to: "/architecture", label: "Architecture", end: false },
  { to: "/dashboard/explainability", label: "Explainability", icon: Eye, end: false },
  { to: "/dashboard/baseline", label: "Baseline Comparison", icon: BarChart3, end: false },
  { to: "/certificate", label: "Sec 65B Certificate", icon: ShieldCheck, end: false },
  { to: "/dashboard", label: "Live Demo", end: false },
];

export function Layout({ children }: { children: ReactNode }) {
  const [isMobileNavOpen, setIsMobileNavOpen] = useState(false);
  const [isDownloadModalOpen, setIsDownloadModalOpen] = useState(false);
  const location = useLocation();

  const isNavActive = (to: string, end?: boolean) => {
    if (end) {
      return location.pathname === to;
    }
    if (to === "/certificate") {
      return (
        location.pathname === "/certificate" ||
        location.pathname === "/dashboard/certificate" ||
        (location.pathname === "/dashboard/blockchain" && location.search.includes("tab=certificate"))
      );
    }
    if (to === "/dashboard") {
      return (
        location.pathname.startsWith("/dashboard") &&
        !location.pathname.startsWith("/dashboard/explainability") &&
        !location.pathname.startsWith("/dashboard/baseline") &&
        !location.pathname.startsWith("/dashboard/certificate") &&
        !(location.pathname === "/dashboard/blockchain" && location.search.includes("tab=certificate"))
      );
    }
    return location.pathname === to || location.pathname.startsWith(`${to}/`);
  };

  return (
    <div className="sentinel-app min-h-screen bg-grid" style={{ backgroundColor: "var(--color-base)" }}>
      <Sparkle3DBackground />
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:bg-[var(--color-accent)] focus:px-4 focus:py-2 focus:text-[var(--color-base)]"
      >
        Skip to content
      </a>

      <header className="sticky top-0 z-40 border-b backdrop-blur-md" style={{ borderColor: "var(--color-border)", backgroundColor: "color-mix(in srgb, var(--color-base) 88%, transparent)" }}>
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-8">
          {/* Left: Brand Identity */}
          <Link to="/" className="flex items-center gap-3 shrink-0" onClick={() => setIsMobileNavOpen(false)}>
            <div
              className="flex h-9 w-9 items-center justify-center rounded-lg shadow-sm"
              style={{ backgroundColor: "color-mix(in srgb, var(--color-accent) 18%, transparent)", border: "1px solid color-mix(in srgb, var(--color-accent) 30%, transparent)" }}
            >
              <Shield size={18} style={{ color: "var(--color-accent)" }} />
            </div>
            <div>
              <div className="text-base font-bold tracking-tight text-[var(--color-text-primary)]">SHIELDNET</div>
              <div className="font-mono text-[9.5px] uppercase tracking-[0.22em] text-[var(--color-text-muted)]">SIH26153 · NTRO</div>
            </div>
          </Link>

          {/* Center: Cleanly Aligned Primary Navigation */}
          <nav className="hidden items-center gap-1.5 xl:gap-2 lg:flex">
            {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => {
              const active = isNavActive(to, end);
              return (
                <Link
                  key={to}
                  to={to}
                  onClick={() => setIsMobileNavOpen(false)}
                  className={`nav-glow inline-flex items-center gap-2 rounded-lg px-3 py-2 text-sm font-medium transition-all ${
                    active
                      ? "active text-[var(--color-accent)] font-semibold shadow-sm"
                      : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-white/5"
                  }`}
                  style={{
                    backgroundColor: active ? "color-mix(in srgb, var(--color-accent) 14%, transparent)" : "transparent",
                    border: active ? "1px solid color-mix(in srgb, var(--color-accent) 25%, transparent)" : "1px solid transparent",
                  }}
                >
                  {Icon && <Icon size={15} className="opacity-85 shrink-0" />}
                  <span>{label}</span>
                </Link>
              );
            })}
          </nav>

          {/* Right: Operational Status, Theme, & User Clearance Controls */}
          <div className="hidden items-center gap-3 lg:flex shrink-0">
            <button
              onClick={() => setIsDownloadModalOpen(true)}
              className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 hover:bg-cyan-500/20 transition-all shadow-sm"
              title="Deploy Local Defense Agents"
            >
              <Download size={13} />
              <span>Deploy Agent</span>
            </button>
            <ThemeToggle />
            <OfflineStatusBadge />
            <AuthBar />
          </div>

          {/* Mobile hamburger menu toggle */}
          <div className="flex items-center gap-2 lg:hidden">
            <ThemeToggle />
            <button
              type="button"
              aria-label="Toggle navigation menu"
              className="inline-flex items-center justify-center rounded-md border p-2 glow-box"
              style={{ borderColor: "var(--color-border)", color: "var(--color-text-primary)" }}
              onClick={() => setIsMobileNavOpen((prev) => !prev)}
            >
              {isMobileNavOpen ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>

        {/* Mobile Navigation Drawer */}
        {isMobileNavOpen && (
          <div className="border-t px-4 py-3 lg:hidden" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
            <nav className="flex flex-col gap-1.5">
              {NAV_ITEMS.map(({ to, label, icon: Icon, end }) => {
                const active = isNavActive(to, end);
                return (
                  <Link
                    key={to}
                    to={to}
                    onClick={() => setIsMobileNavOpen(false)}
                    className={`nav-glow inline-flex items-center gap-2.5 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors ${
                      active
                        ? "active text-[var(--color-accent)] font-semibold"
                        : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
                    }`}
                    style={{
                      backgroundColor: active ? "color-mix(in srgb, var(--color-accent) 14%, transparent)" : "transparent",
                      border: active ? "1px solid color-mix(in srgb, var(--color-accent) 25%, transparent)" : "1px solid transparent",
                    }}
                  >
                    {Icon && <Icon size={16} className="opacity-85 shrink-0" />}
                    <span>{label}</span>
                  </Link>
                );
              })}
            </nav>
            <div className="mt-3 flex items-center justify-between gap-3 border-t pt-3" style={{ borderColor: "var(--color-border)" }}>
              <OfflineStatusBadge />
              <AuthBar />
            </div>
          </div>
        )}
      </header>

      <main id="main-content" className="relative z-10 mx-auto w-full max-w-[1600px] px-4 py-8 sm:px-6 lg:px-8">
        {children}
      </main>

      <footer className="relative z-10 border-t" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-6 sm:px-6 lg:px-8">
          <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
            <div>
              <div className="text-base font-semibold text-[var(--color-text-primary)]">Forecasting attacks before they complete.</div>
              <div className="mt-1 text-sm text-[var(--color-text-secondary)]">SHIELDNET helps defenders see the next state of the network before compromise.</div>
            </div>
            <div className="inline-flex w-fit items-center rounded-full border px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.18em] text-[var(--color-text-secondary)]" style={{ borderColor: "var(--color-border)" }}>
              ShieldNet · NTRO · Blockchain &amp; Cybersecurity
            </div>
          </div>

          <div className="flex flex-col gap-3 border-t pt-4 text-sm md:flex-row md:items-center md:justify-between" style={{ borderColor: "var(--color-border)" }}>
            <div className="font-mono text-xs text-[var(--color-text-muted)]">
              Offline Neural World Model Architecture (Constraint C4 Compliant)
            </div>
            <div className="flex flex-wrap items-center gap-4 text-[var(--color-text-muted)]">
              <Link to="/" className="hover:text-[var(--color-text-primary)]">Home</Link>
              <Link to="/about" className="hover:text-[var(--color-text-primary)]">About</Link>
              <Link to="/architecture" className="hover:text-[var(--color-text-primary)]">Architecture</Link>
              <Link to="/dashboard/explainability" className="hover:text-[var(--color-text-primary)]">Explainability</Link>
              <Link to="/dashboard/baseline" className="hover:text-[var(--color-text-primary)]">Baseline Comparison</Link>
              <Link to="/dashboard" className="hover:text-[var(--color-text-primary)]">Live Demo</Link>
            </div>
          </div>
        </div>
      </footer>

      <DownloadAgentModal
        isOpen={isDownloadModalOpen}
        onClose={() => setIsDownloadModalOpen(false)}
      />
    </div>
  );
}

