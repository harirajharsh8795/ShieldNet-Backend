import { useState, useEffect, useRef } from "react";
import {
  Shield,
  UserCheck,
  Key,
  ChevronDown,
  CheckCircle2,
  LogOut,
  UserPlus,
  LogIn,
  Building,
  Check,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";
import { fetchEnterprisePersonas } from "../data/api";

export function AuthBar() {
  const { user, isAuthenticated, login, logout, openAuthModal, isLoading } = useAuth();
  const [personas, setPersonas] = useState<any[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isSwitching, setIsSwitching] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    fetchEnterprisePersonas().then(setPersonas).catch(() => {});
  }, []);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleSelectPersona = async (persona: any) => {
    setIsSwitching(true);
    setIsOpen(false);
    const pwdMap: Record<string, string> = {
      "soc-analyst@ntro.gov.in": "ShieldNet@Defense2026",
      "admin@shieldnet.local": "Admin@123",
      "analyst@shieldnet.local": "Analyst@123",
      "auditor@shieldnet.local": "Auditor@123",
      "admin@shieldnet.gov.in": "shieldnet2026",
      "analyst@shieldnet.gov.in": "analyst2026",
      "auditor@shieldnet.gov.in": "auditor2026",
    };
    const password = pwdMap[persona.username] || "ShieldNet@Defense2026";
    try {
      await login(persona.username, password);
    } catch (err: any) {
      console.error("Persona switch failed:", err);
      alert(`Persona switch failed: ${err?.message || "Invalid credentials"}`);
    } finally {
      setIsSwitching(false);
    }
  };

  const getRoleColor = (role?: string) => {
    if (!role) return "var(--color-text-muted)";
    const r = role.toLowerCase();
    if (r.includes("ciso") || r.includes("admin")) return "#10B981"; // Emerald
    if (r.includes("analyst")) return "#3B82F6"; // Blue
    if (r.includes("auditor")) return "#F59E0B"; // Amber
    return "#8B5CF6"; // Purple
  };

  // Helper to get initials from officer name or username
  const getInitials = (name?: string, username?: string): string => {
    if (name) {
      const parts = name.replace(/[()]/g, "").trim().split(/\s+/).filter(Boolean);
      if (parts.length >= 2) {
        return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
      }
      if (parts.length === 1 && parts[0].length >= 2) {
        return parts[0].substring(0, 2).toUpperCase();
      }
    }
    if (username) {
      const clean = username.split("@")[0].replace(/[^a-zA-Z]/g, "");
      if (clean.length >= 2) return clean.substring(0, 2).toUpperCase();
    }
    return "SO";
  };

  // 1. If user is not authenticated, render a SINGLE prominent Login / Sign Up button
  if (!isAuthenticated || !user) {
    return (
      <button
        type="button"
        id="navbar-auth-btn"
        onClick={() => openAuthModal("login")}
        className="inline-flex items-center gap-2 rounded-xl px-3.5 py-1.5 text-xs font-semibold border transition-all cursor-pointer shadow-sm hover:shadow-cyan-500/20 group"
        style={{
          background: "linear-gradient(135deg, rgba(34, 211, 238, 0.14) 0%, rgba(59, 130, 246, 0.14) 100%)",
          borderColor: "rgba(34, 211, 238, 0.45)",
          color: "#22d3ee",
        }}
        title="Access ShieldNet Command Terminal (Login / Sign Up)"
      >
        <div className="flex h-5 w-5 items-center justify-center rounded-lg bg-cyan-500/20 text-cyan-400 group-hover:scale-110 transition-transform">
          <LogIn size={13} />
        </div>
        <span className="font-semibold tracking-wide text-cyan-300 group-hover:text-cyan-200">
          Login / Sign Up
        </span>
      </button>
    );
  }

  const officerName = user.display_name || user.username.split("@")[0] || "Officer";
  const officerInitials = getInitials(user.display_name, user.username);
  const roleColor = getRoleColor(user.role);

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Active Officer Identity Pill */}
      <button
        type="button"
        id="authenticated-user-pill"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 rounded-xl border px-2.5 sm:px-3 py-1.5 text-xs font-medium transition-all hover:bg-[var(--color-panel)] cursor-pointer"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "color-mix(in srgb, var(--color-panel) 85%, transparent)",
        }}
        title={`Authenticated as ${officerName} (${user.role} - ${user.clearance_label || `Level ${user.clearance_level}`})`}
      >
        {/* Officer Avatar with Initials */}
        <div
          className="flex h-6 w-6 items-center justify-center rounded-lg shrink-0 text-[10px] font-bold font-mono shadow-sm"
          style={{
            backgroundColor: `${roleColor}25`,
            color: roleColor,
            border: `1px solid ${roleColor}50`,
          }}
        >
          {officerInitials}
        </div>

        {/* Officer Display Name & Role */}
        <div className="text-left block max-w-[120px] sm:max-w-[180px]">
          <div className="flex items-center gap-1.5 leading-tight">
            <span className="font-bold text-[var(--color-text-primary)] text-xs truncate">
              {officerName}
            </span>
            <span
              className="inline-block h-2 w-2 rounded-full animate-pulse shrink-0"
              style={{ backgroundColor: roleColor }}
              title="Session Active"
            />
          </div>
          <div className="text-[10px] text-[var(--color-text-muted)] leading-tight font-mono truncate">
            {user.role} · L{user.clearance_level || 5}
          </div>
        </div>

        <ChevronDown size={12} className="text-[var(--color-text-muted)] shrink-0" />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div
          className="absolute right-0 mt-2 w-80 rounded-2xl border p-3 shadow-2xl z-50 backdrop-blur-xl animate-in fade-in slide-in-from-top-2 duration-150"
          style={{
            backgroundColor: "var(--color-panel, #151b2b)",
            borderColor: "color-mix(in srgb, var(--color-border) 80%, var(--color-accent) 20%)",
            boxShadow: "0 20px 40px -15px rgba(0,0,0,0.8), 0 0 25px -5px rgba(34,211,238,0.15)",
          }}
        >
          {/* Active Session Header */}
          <div className="px-2 py-2 border-b" style={{ borderColor: "var(--color-border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-[9.5px] uppercase tracking-wider font-mono font-semibold text-[var(--color-text-muted)]">
                OAuth2 / Sovereign Session
              </span>
              <span className="text-[9.5px] text-emerald-400 font-mono flex items-center gap-1">
                <CheckCircle2 size={10} /> Active Token
              </span>
            </div>

            <div className="mt-1.5 flex items-center gap-2">
              <div
                className="flex h-7 w-7 items-center justify-center rounded-lg shrink-0"
                style={{
                  backgroundColor: `${getRoleColor(user.role)}25`,
                  color: getRoleColor(user.role),
                }}
              >
                {user.role?.includes("CISO") || user.role?.includes("Admin") ? (
                  <Shield size={14} />
                ) : user.role?.includes("Auditor") ? (
                  <Key size={14} />
                ) : (
                  <UserCheck size={14} />
                )}
              </div>
              <div className="overflow-hidden">
                <div className="text-xs font-bold text-[var(--color-text-primary)] truncate">
                  {user.display_name}
                </div>
                <div className="text-[10px] font-mono text-[var(--color-text-muted)] truncate">
                  {user.username}
                </div>
              </div>
            </div>

            <div className="mt-2 flex flex-wrap items-center gap-1.5">
              <span
                className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-semibold uppercase tracking-wider"
                style={{
                  backgroundColor: `${getRoleColor(user.role)}15`,
                  color: getRoleColor(user.role),
                  border: `1px solid ${getRoleColor(user.role)}30`,
                }}
              >
                {user.clearance_label || `Clearance Level ${user.clearance_level}`}
              </span>
              {user.department && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] text-[var(--color-text-muted)] border border-[var(--color-border)] truncate max-w-[180px]">
                  <Building size={9} />
                  <span className="truncate">{user.department}</span>
                </span>
              )}
            </div>

            {/* Permissions summary */}
            {user.permissions && user.permissions.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {user.permissions.slice(0, 4).map((perm) => (
                  <span
                    key={perm}
                    className="font-mono text-[8.5px] px-1.5 py-0.5 rounded bg-black/30 text-[var(--color-text-muted)] border border-[var(--color-border)]"
                  >
                    {perm}
                  </span>
                ))}
                {user.permissions.length > 4 && (
                  <span className="font-mono text-[8.5px] px-1 py-0.5 rounded text-[var(--color-text-muted)]">
                    +{user.permissions.length - 4} more
                  </span>
                )}
              </div>
            )}
          </div>

          {/* Persona Switcher Section */}
          <div className="py-2">
            <div className="px-2 py-1 text-[9.5px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center justify-between">
              <span>Switch Active Persona (Evaluation):</span>
              {isSwitching && <span className="text-cyan-400 font-mono text-[9px]">Switching...</span>}
            </div>

            <div className="space-y-1 mt-1">
              {personas.map((p) => {
                const isSelected = user.username === p.username || user.role === p.role;
                return (
                  <button
                    key={p.username}
                    type="button"
                    onClick={() => handleSelectPersona(p)}
                    disabled={isSwitching || isLoading}
                    className="w-full flex items-center justify-between px-2.5 py-1.5 text-xs rounded-xl text-left transition-colors cursor-pointer"
                    style={{
                      backgroundColor: isSelected
                        ? "color-mix(in srgb, var(--color-accent, #22d3ee) 12%, transparent)"
                        : "transparent",
                    }}
                  >
                    <div className="flex items-center gap-2 truncate">
                      <span
                        className="h-2 w-2 rounded-full shrink-0"
                        style={{ backgroundColor: getRoleColor(p.role) }}
                      />
                      <div className="truncate">
                        <div className="font-semibold text-[var(--color-text-primary)] text-[11px] truncate">
                          {p.display_name || p.role}
                        </div>
                        <div className="text-[9.5px] text-[var(--color-text-muted)] truncate font-mono">
                          {p.username}
                        </div>
                      </div>
                    </div>
                    {isSelected ? (
                      <Check size={13} className="text-emerald-400 shrink-0" />
                    ) : (
                      <span className="text-[9px] font-mono text-[var(--color-text-muted)]">
                        L{p.clearance_level}
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Action Footer */}
          <div className="border-t pt-2 mt-1 space-y-1" style={{ borderColor: "var(--color-border)" }}>
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                openAuthModal("signup");
              }}
              className="w-full flex items-center gap-2 px-2.5 py-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-white/5 rounded-lg transition-colors cursor-pointer"
            >
              <UserPlus size={13} className="text-cyan-400" />
              <span>Enroll New Defense Operator</span>
            </button>

            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                logout();
              }}
              className="w-full flex items-center gap-2 px-2.5 py-1.5 text-xs text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded-lg transition-colors font-medium cursor-pointer"
            >
              <LogOut size={13} />
              <span>Lock Terminal &amp; Sign Out</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
