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
      "admin@shieldnet.local": "Admin@123",
      "analyst@shieldnet.local": "Analyst@123",
      "auditor@shieldnet.local": "Auditor@123",
      "admin@shieldnet.gov.in": "shieldnet2026",
      "analyst@shieldnet.gov.in": "analyst2026",
      "auditor@shieldnet.gov.in": "auditor2026",
    };
    const password = pwdMap[persona.username] || "Admin@123";
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

  // If user is not authenticated, render prominent Login and Sign Up triggers
  if (!isAuthenticated || !user) {
    return (
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => openAuthModal("login")}
          className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 hover:bg-cyan-500/25 transition-all shadow-sm cursor-pointer"
        >
          <LogIn size={13} />
          <span>Login</span>
        </button>
        <button
          type="button"
          onClick={() => openAuthModal("signup")}
          className="inline-flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-xs font-semibold bg-emerald-500/15 text-emerald-400 border border-emerald-500/40 hover:bg-emerald-500/25 transition-all shadow-sm cursor-pointer"
        >
          <UserPlus size={13} />
          <span>Sign Up</span>
        </button>
      </div>
    );
  }

  return (
    <div className="relative" ref={dropdownRef}>
      {/* Active Persona Pill */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 rounded-xl border px-3 py-1.5 text-xs font-medium transition-all hover:bg-[var(--color-panel)] cursor-pointer"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "color-mix(in srgb, var(--color-panel) 85%, transparent)",
        }}
        title={`Authenticated as ${user.display_name} (${user.role})`}
      >
        <div
          className="flex h-5 w-5 items-center justify-center rounded-full shrink-0"
          style={{
            backgroundColor: `${getRoleColor(user.role)}20`,
            color: getRoleColor(user.role),
          }}
        >
          {user.role?.includes("CISO") || user.role?.includes("Admin") ? (
            <Shield size={12} />
          ) : user.role?.includes("Auditor") ? (
            <Key size={12} />
          ) : (
            <UserCheck size={12} />
          )}
        </div>

        <div className="text-left hidden lg:block">
          <div className="flex items-center gap-1.5 leading-tight">
            <span className="font-semibold text-[var(--color-text-primary)]">
              {user.role}
            </span>
            <span
              className="inline-block h-1.5 w-1.5 rounded-full animate-pulse"
              style={{ backgroundColor: getRoleColor(user.role) }}
            />
          </div>
          <div className="text-[10px] text-[var(--color-text-muted)] leading-tight font-mono">
            {user.clearance_label?.split("-")[0]?.trim() || `Level ${user.clearance_level || 5}`}
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
                          {p.role}
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
