import { useState, useEffect } from "react";
import { Shield, UserCheck, Key, Lock, ChevronDown, CheckCircle2, LogOut } from "lucide-react";
import { loginOAuth2, fetchEnterprisePersonas, logoutOAuth2 } from "../data/api";

export function AuthBar() {
  const [currentUser, setCurrentUser] = useState<any>(() => {
    const saved = localStorage.getItem("shieldnet_user");
    return saved
      ? JSON.parse(saved)
      : {
          username: "admin@shieldnet.gov.in",
          display_name: "Chief Information Security Officer (CISO)",
          role: "CISO_Admin",
          clearance_level: 5,
          clearance_label: "Level 5 - Sovereign Defense"
        };
  });

  const [personas, setPersonas] = useState<any[]>([]);
  const [isOpen, setIsOpen] = useState(false);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [customUsername, setCustomUsername] = useState("");
  const [customPassword, setCustomPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [isAuthenticating, setIsAuthenticating] = useState(false);

  useEffect(() => {
    fetchEnterprisePersonas().then(setPersonas);
  }, []);

  const handleSelectPersona = async (persona: any) => {
    setIsAuthenticating(true);
    setIsOpen(false);
    const pwdMap: Record<string, string> = {
      "admin@shieldnet.gov.in": "shieldnet2026",
      "analyst@shieldnet.gov.in": "analyst2026",
      "auditor@shieldnet.gov.in": "auditor2026"
    };
    const password = pwdMap[persona.username] || "shieldnet2026";
    try {
      const res = await loginOAuth2(persona.username, password);
      if (res && res.user) {
        setCurrentUser(res.user);
      }
    } catch (err: any) {
      console.error("Persona authentication failed:", err);
      alert(`SSO Authentication failed: ${err?.message || "Invalid credentials"}`);
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleCustomLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoginError("");
    setIsAuthenticating(true);
    try {
      const res = await loginOAuth2(customUsername, customPassword);
      if (res && res.user) {
        setCurrentUser(res.user);
        setIsLoginModalOpen(false);
        setCustomUsername("");
        setCustomPassword("");
      }
    } catch (err: any) {
      setLoginError(err?.message || "Invalid credentials or user not authorized in IdP directory.");
    } finally {
      setIsAuthenticating(false);
    }
  };

  const handleLogout = () => {
    logoutOAuth2();
    setCurrentUser(null);
    setIsOpen(false);
  };

  const getRoleColor = (role?: string) => {
    if (!role) return "var(--color-text-muted)";
    const r = role.toLowerCase();
    if (r.includes("ciso") || r.includes("admin")) return "#10B981"; // Emerald
    if (r.includes("analyst")) return "#3B82F6"; // Blue
    if (r.includes("auditor")) return "#F59E0B"; // Amber
    return "#8B5CF6"; // Purple
  };

  return (
    <div className="relative">
      {/* Active Persona Pill / Button */}
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="flex items-center gap-2 rounded-lg border px-2.5 py-1.5 text-xs font-medium transition-all hover:bg-[var(--color-panel)]"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "color-mix(in srgb, var(--color-panel) 85%, transparent)"
        }}
        title="Enterprise SSO / Role-Based Access Control"
      >
        <div
          className="flex h-5 w-5 items-center justify-center rounded-full"
          style={{ backgroundColor: `${getRoleColor(currentUser?.role)}20`, color: getRoleColor(currentUser?.role) }}
        >
          {currentUser?.role?.includes("CISO") || currentUser?.role?.includes("Admin") ? (
            <Shield size={12} />
          ) : currentUser?.role?.includes("Auditor") ? (
            <Key size={12} />
          ) : (
            <UserCheck size={12} />
          )}
        </div>

        <div className="text-left hidden lg:block">
          <div className="flex items-center gap-1.5 leading-tight">
            <span className="font-semibold text-[var(--color-text-primary)]">
              {currentUser ? currentUser.role : "Guest SSO"}
            </span>
            <span
              className="inline-block h-1.5 w-1.5 rounded-full"
              style={{ backgroundColor: getRoleColor(currentUser?.role) }}
            />
          </div>
          <div className="text-[10px] text-[var(--color-text-muted)] leading-tight">
            {currentUser?.clearance_label?.split("-")[0] || "Level 5"}
          </div>
        </div>

        <ChevronDown size={12} className="text-[var(--color-text-muted)]" />
      </button>

      {/* Dropdown Menu */}
      {isOpen && (
        <div
          className="absolute right-0 mt-2 w-72 rounded-xl border p-2 shadow-2xl z-50 backdrop-blur-md"
          style={{
            backgroundColor: "var(--color-panel)",
            borderColor: "var(--color-border)"
          }}
        >
          <div className="px-3 py-2 border-b" style={{ borderColor: "var(--color-border)" }}>
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-wider font-semibold text-[var(--color-text-muted)]">
                OAuth2 Enterprise IdP
              </span>
              <span className="text-[10px] text-emerald-400 font-mono flex items-center gap-1">
                <CheckCircle2 size={10} /> OIDC Active
              </span>
            </div>
            <div className="mt-1 text-xs font-semibold text-[var(--color-text-primary)] truncate">
              {currentUser?.display_name || "Enterprise Session"}
            </div>
            <div className="text-[10px] font-mono text-[var(--color-text-muted)] truncate">
              {currentUser?.username || "offline_demo@shieldnet"}
            </div>
          </div>

          <div className="py-1">
            <div className="px-3 py-1 text-[10px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)]">
              Quick-Switch Persona (RBAC Testing):
            </div>
            {personas.map((p) => {
              const isSelected = currentUser?.role === p.role;
              return (
                <button
                  key={p.username}
                  type="button"
                  onClick={() => handleSelectPersona(p)}
                  disabled={isAuthenticating}
                  className="w-full flex items-center justify-between px-3 py-2 text-xs rounded-lg text-left transition-colors hover:bg-[color-mix(in_srgb,var(--color-accent)_10%,transparent)]"
                  style={{
                    backgroundColor: isSelected
                      ? "color-mix(in srgb, var(--color-accent) 12%, transparent)"
                      : "transparent"
                  }}
                >
                  <div className="flex items-center gap-2 truncate">
                    <span
                      className="h-2 w-2 rounded-full"
                      style={{ backgroundColor: getRoleColor(p.role) }}
                    />
                    <div>
                      <div className="font-medium text-[var(--color-text-primary)]">{p.role}</div>
                      <div className="text-[10px] text-[var(--color-text-muted)]">{p.clearance_label}</div>
                    </div>
                  </div>
                  {isSelected && <CheckCircle2 size={14} className="text-emerald-400" />}
                </button>
              );
            })}
          </div>

          <div className="border-t pt-1 mt-1" style={{ borderColor: "var(--color-border)" }}>
            <button
              type="button"
              onClick={() => {
                setIsOpen(false);
                setIsLoginModalOpen(true);
              }}
              className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[color-mix(in_srgb,var(--color-accent)_8%,transparent)] rounded-md"
            >
              <Lock size={12} />
              Manual OAuth2 Login
            </button>

            {currentUser && (
              <button
                type="button"
                onClick={handleLogout}
                className="w-full flex items-center gap-2 px-3 py-1.5 text-xs text-rose-400 hover:bg-rose-500/10 rounded-md"
              >
                <LogOut size={12} />
                Sign Out Session
              </button>
            )}
          </div>
        </div>
      )}

      {/* Manual Login Modal */}
      {isLoginModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div
            className="w-full max-w-md rounded-2xl border p-6 shadow-2xl"
            style={{ backgroundColor: "var(--color-panel)", borderColor: "var(--color-border)" }}
          >
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <Shield size={20} className="text-[var(--color-accent)]" />
                <h3 className="text-base font-semibold text-[var(--color-text-primary)]">
                  Enterprise OAuth2 / OIDC Login
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setIsLoginModalOpen(false)}
                className="text-sm text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
              >
                ✕
              </button>
            </div>

            <form onSubmit={handleCustomLogin} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-[var(--color-text-secondary)] mb-1">
                  Enterprise Username / Email
                </label>
                <input
                  type="text"
                  value={customUsername}
                  onChange={(e) => setCustomUsername(e.target.value)}
                  placeholder="admin@shieldnet.gov.in"
                  required
                  className="w-full rounded-lg border px-3 py-2 text-xs text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
                  style={{ backgroundColor: "var(--color-base)", borderColor: "var(--color-border)" }}
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[var(--color-text-secondary)] mb-1">
                  Password (PBKDF2-HMAC-SHA256)
                </label>
                <input
                  type="password"
                  value={customPassword}
                  onChange={(e) => setCustomPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full rounded-lg border px-3 py-2 text-xs text-[var(--color-text-primary)] outline-none focus:border-[var(--color-accent)]"
                  style={{ backgroundColor: "var(--color-base)", borderColor: "var(--color-border)" }}
                />
              </div>

              {loginError && (
                <div className="text-xs text-rose-400 bg-rose-500/10 p-2 rounded border border-rose-500/20">
                  {loginError}
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2">
                <button
                  type="button"
                  onClick={() => setIsLoginModalOpen(false)}
                  className="px-4 py-2 text-xs font-medium rounded-lg border text-[var(--color-text-secondary)] hover:bg-[var(--color-panel)]"
                  style={{ borderColor: "var(--color-border)" }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isAuthenticating}
                  className="px-4 py-2 text-xs font-semibold rounded-lg bg-[var(--color-accent)] text-[var(--color-base)] hover:opacity-90 disabled:opacity-50"
                >
                  {isAuthenticating ? "Verifying Token..." : "Authenticate"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
