import { NavLink, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { Activity, Upload, Bell, Radio, Lock } from "lucide-react";
import { UploadPage } from "./UploadPage";
import { SimulationPage } from "./SimulationPage";
import { LiveMonitorPage } from "./LiveMonitorPage";
import { AlertSentinelPage } from "./AlertSentinelPage";
import { BlockchainAuditPage } from "./BlockchainAuditPage";

const tabs = [
  { to: "/dashboard", label: "Upload", icon: Upload, end: true },
  { to: "/dashboard/live", label: "Live Sniffer", icon: Radio },
  { to: "/dashboard/simulation", label: "Scenario Simulation", icon: Activity },
  { to: "/dashboard/alerts", label: "Alerts (WhatsApp & Custom IP)", icon: Bell, highlight: true },
  { to: "/dashboard/blockchain", label: "Immutable Ledger (SIERL)", icon: Lock, highlight: true },
];

export function DashboardPage() {
  const location = useLocation();

  const renderTabContent = () => {
    if (location.pathname === "/dashboard" || location.pathname === "/dashboard/") return <UploadPage />;
    if (location.pathname === "/dashboard/live") return <LiveMonitorPage />;
    if (location.pathname === "/dashboard/simulation") return <SimulationPage />;
    if (location.pathname === "/dashboard/alerts") return <AlertSentinelPage />;
    if (location.pathname === "/dashboard/blockchain") return <BlockchainAuditPage />;
    return <UploadPage />;
  };

  return (
    <div className="w-full pb-8">
      <div className="mb-6 flex flex-wrap items-center gap-2 rounded-xl border p-2 glow-box" style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}>
        {tabs.map(({ to, label, icon: Icon, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `inline-flex items-center gap-2 rounded-md px-3.5 py-2 text-sm font-medium transition-colors ${
                isActive ? "text-[var(--color-accent)]" : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`
            }
            style={({ isActive }) => ({
              backgroundColor: isActive ? "color-mix(in srgb, var(--color-accent) 12%, transparent)" : "transparent",
              border: isActive ? "1px solid color-mix(in srgb, var(--color-accent) 35%, var(--color-border))" : "1px solid transparent",
            })}
          >
            <Icon size={15} />
            {label}
          </NavLink>
        ))}
      </div>

      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: "easeOut" }}
      >
        {renderTabContent()}
      </motion.div>
    </div>
  );
}
