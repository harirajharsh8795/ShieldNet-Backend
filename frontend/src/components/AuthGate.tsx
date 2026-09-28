import React, { useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import {
  Shield,
  Lock,
  UserCheck,
  Key,
  AlertTriangle,
  ChevronRight,
  Eye,
  EyeOff,
  UserPlus,
  LogIn,
  Building,
  User,
  Fingerprint,
  Zap,
  ArrowLeft,
} from "lucide-react";
import { useAuth } from "../context/AuthContext";

export function AuthGate() {
  const {
    isAuthenticated,
    authMode,
    setAuthMode,
    isAuthModalOpen,
    closeAuthModal,
  } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  const isPublicPage =
    location.pathname === "/" ||
    location.pathname === "/about" ||
    location.pathname === "/architecture";
  const isProtectedPage = !isPublicPage;

  // 1. If already authenticated and modal is not explicitly triggered, do not render
  if (isAuthenticated && !isAuthModalOpen) {
    return null;
  }

  // 2. If NOT authenticated, but on a public page and modal wasn't explicitly triggered:
  // Allow user to view landing page freely!
  if (!isAuthenticated && isPublicPage && !isAuthModalOpen) {
    return null;
  }

  const handleDismiss = () => {
    closeAuthModal();
    if (isProtectedPage && !isAuthenticated) {
      navigate("/");
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 overflow-y-auto animate-in fade-in duration-200"
      style={{
        backgroundColor: "rgba(5, 9, 18, 0.94)",
        backdropFilter: "blur(20px)",
        WebkitBackdropFilter: "blur(20px)",
      }}
      role="dialog"
      aria-modal="true"
      aria-labelledby="auth-modal-title"
    >
      <div className="relative w-full max-w-2xl my-auto">
        {/* Glowing border wrapper */}
        <div
          className="relative rounded-2xl border p-6 sm:p-8 shadow-2xl overflow-hidden"
          style={{
            backgroundColor: "var(--color-panel, #111827)",
            borderColor: "color-mix(in srgb, var(--color-accent, #22d3ee) 40%, var(--color-border, #1f2937))",
            boxShadow:
              "0 25px 50px -12px rgba(0, 0, 0, 0.7), 0 0 40px -10px color-mix(in srgb, var(--color-accent, #22d3ee) 25%, transparent)",
          }}
        >
          {/* Background cyber accent elements */}
          <div
            className="pointer-events-none absolute -top-24 -right-24 h-64 w-64 rounded-full opacity-20 blur-3xl"
            style={{ backgroundColor: "var(--color-accent, #22d3ee)" }}
          />
          <div
            className="pointer-events-none absolute -bottom-24 -left-24 h-64 w-64 rounded-full opacity-15 blur-3xl"
            style={{ backgroundColor: "var(--color-accent-secondary, #3b82f6)" }}
          />

          {/* Dismiss button */}
          <div className="absolute top-5 right-5 flex items-center gap-2">
            {isProtectedPage && !isAuthenticated ? (
              <button
                type="button"
                onClick={handleDismiss}
                className="text-xs font-mono text-[var(--color-text-muted)] hover:text-cyan-400 rounded-lg border px-2.5 py-1.5 transition-all flex items-center gap-1.5 cursor-pointer"
                style={{ borderColor: "var(--color-border)", backgroundColor: "rgba(0,0,0,0.4)" }}
                title="Return to Public Landing Page"
              >
                <ArrowLeft size={13} />
                <span>Public Home</span>
              </button>
            ) : (
              <button
                type="button"
                onClick={handleDismiss}
                className="text-xs font-mono text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] rounded-lg border px-2.5 py-1.5 transition-all cursor-pointer"
                style={{ borderColor: "var(--color-border)", backgroundColor: "rgba(0,0,0,0.4)" }}
                title="Close Modal"
              >
                ESC / Close
              </button>
            )}
          </div>

          {/* Header Banner */}
          <div className="flex flex-col items-center text-center mb-6">
            <div
              className="relative flex h-14 w-14 items-center justify-center rounded-2xl shadow-lg mb-3"
              style={{
                backgroundColor: "color-mix(in srgb, var(--color-accent, #22d3ee) 15%, transparent)",
                border: "1px solid color-mix(in srgb, var(--color-accent, #22d3ee) 45%, transparent)",
              }}
            >
              <Shield size={28} style={{ color: "var(--color-accent, #22d3ee)" }} />
              <span className="absolute -top-1 -right-1 flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-cyan-500"></span>
              </span>
            </div>

            <div className="inline-flex items-center gap-2 rounded-full px-3 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-widest text-cyan-400 border border-cyan-500/30 bg-cyan-950/40 mb-2">
              <Fingerprint size={12} />
              <span>
                {isProtectedPage && !isAuthenticated
                  ? "Operational Clearance Required"
                  : "Sovereign Zero-Trust Identity Gateway"}
              </span>
            </div>

            <h2
              id="auth-modal-title"
              className="text-xl sm:text-2xl font-bold tracking-tight text-[var(--color-text-primary)] font-mono"
            >
              SHIELDNET CYBER COMMAND GATE
            </h2>
            <p className="mt-1 text-xs text-[var(--color-text-secondary)] max-w-md">
              {isProtectedPage && !isAuthenticated
                ? "Live network intrusion forecasting, simulation trajectories, and blockchain ledger evidence are restricted. Enter credentials or use quick evaluation personas below to unlock."
                : "National Critical Information Infrastructure Protection (NTRO SIH26153). Valid security clearance credentials required to decrypt command console."}
            </p>
          </div>

          {/* Security Gate Mode Tabs */}
          <div
            className="flex rounded-xl p-1 mb-6 border"
            style={{
              backgroundColor: "color-mix(in srgb, var(--color-base, #0a0e17) 70%, transparent)",
              borderColor: "var(--color-border, #1f2937)",
            }}
          >
            <button
              type="button"
              onClick={() => setAuthMode("login")}
              className={`flex-1 flex items-center justify-center gap-2 py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                authMode === "login"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                  : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              <LogIn size={14} />
              <span>AUTHENTICATE (SIGN IN)</span>
            </button>
            <button
              type="button"
              onClick={() => setAuthMode("signup")}
              className={`flex-1 flex items-center justify-center gap-2 py-2 text-xs font-semibold rounded-lg transition-all cursor-pointer ${
                authMode === "signup"
                  ? "bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm"
                  : "text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
              }`}
            >
              <UserPlus size={14} />
              <span>NEW ENROLLMENT (SIGN UP)</span>
            </button>
          </div>

          {/* Tab Content */}
          {authMode === "login" ? (
            <LoginForm onSwitchMode={() => setAuthMode("signup")} />
          ) : (
            <SignupForm onSwitchMode={() => setAuthMode("login")} />
          )}

          {/* Footer Security Badges */}
          <div
            className="mt-6 pt-4 border-t flex flex-wrap items-center justify-between gap-3 text-[10px] text-[var(--color-text-muted)] font-mono"
            style={{ borderColor: "var(--color-border)" }}
          >
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400"></span>
              <span>PBKDF2-HMAC-SHA256 (100k iters)</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-cyan-400"></span>
              <span>OAuth 2.0 / RFC 6749 Compliant</span>
            </div>
            <div className="text-right">
              <span>IT Act §66F &amp; §70 Protected</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// SIGN IN COMPONENT
// -----------------------------------------------------------------------------
function LoginForm({ onSwitchMode }: { onSwitchMode: () => void }) {
  const { login, isLoading, targetPath, setTargetPath } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [username, setUsername] = useState("admin@shieldnet.local");
  const [password, setPassword] = useState("Admin@123");
  const [showPassword, setShowPassword] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const handlePostAuthRedirect = () => {
    if (targetPath) {
      const dest = targetPath;
      setTargetPath(null);
      navigate(dest);
    } else if (
      location.pathname === "/" ||
      location.pathname === "/about" ||
      location.pathname === "/architecture"
    ) {
      navigate("/dashboard");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");
    try {
      await login(username.trim(), password.trim());
      handlePostAuthRedirect();
    } catch (err: any) {
      setErrorMsg(err?.message || "Invalid defense credentials. Please check or use quick personas.");
    }
  };

  const handleQuickPersona = async (userStr: string, passStr: string) => {
    setUsername(userStr);
    setPassword(passStr);
    setErrorMsg("");
    try {
      await login(userStr, passStr);
      handlePostAuthRedirect();
    } catch (err: any) {
      setErrorMsg(err?.message || "Persona authentication failed.");
    }
  };

  return (
    <div className="space-y-5">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-1.5">
            Enterprise Email / Sovereign Call-Sign
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-muted)]">
              <User size={15} />
            </div>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="admin@shieldnet.local or officer@shieldnet.gov.in"
              className="w-full rounded-xl border pl-9 pr-3 py-2.5 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)] font-mono"
              style={{
                backgroundColor: "var(--color-base, #0a0e17)",
                borderColor: "var(--color-border, #1f2937)",
              }}
            />
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1.5">
            <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)]">
              Security Key / Password
            </label>
            <span className="text-[10px] text-cyan-400 font-mono">HS256 PBKDF2</span>
          </div>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-muted)]">
              <Lock size={15} />
            </div>
            <input
              type={showPassword ? "text" : "password"}
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="••••••••••••"
              className="w-full rounded-xl border pl-9 pr-10 py-2.5 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)] font-mono"
              style={{
                backgroundColor: "var(--color-base, #0a0e17)",
                borderColor: "var(--color-border, #1f2937)",
              }}
            />
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              className="absolute inset-y-0 right-0 pr-3 flex items-center text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)] cursor-pointer"
            >
              {showPassword ? <EyeOff size={15} /> : <Eye size={15} />}
            </button>
          </div>
        </div>

        {errorMsg && (
          <div className="flex items-center gap-2 p-3 rounded-xl border border-rose-500/30 bg-rose-950/20 text-xs text-rose-300">
            <AlertTriangle size={15} className="shrink-0 text-rose-400" />
            <span>{errorMsg}</span>
          </div>
        )}

        <button
          type="submit"
          disabled={isLoading}
          className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-bold uppercase tracking-wider text-black transition-all shadow-lg hover:opacity-95 disabled:opacity-50 cursor-pointer"
          style={{
            background: "linear-gradient(135deg, #22d3ee 0%, #38bdf8 50%, #0284c7 100%)",
            boxShadow: "0 0 20px rgba(34, 211, 238, 0.35)",
          }}
        >
          {isLoading ? (
            <>
              <div className="h-4 w-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
              <span>Verifying Cryptographic Credentials...</span>
            </>
          ) : (
            <>
              <Key size={15} />
              <span>Authenticate &amp; Unlock Console</span>
            </>
          )}
        </button>
      </form>

      {/* QUICK 1-CLICK PERSONAS FOR JUDGES & EVALUATION */}
      <div className="pt-2 border-t" style={{ borderColor: "var(--color-border)" }}>
        <div className="flex items-center justify-between mb-2.5">
          <span className="text-[10px] font-semibold uppercase tracking-wider text-[var(--color-text-muted)] flex items-center gap-1">
            <Zap size={11} className="text-amber-400" />
            Quick 1-Click Evaluation Personas:
          </span>
          <span className="text-[10px] text-[var(--color-text-muted)]">Instant Verification</span>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
          {/* Persona 1: CISO Admin */}
          <button
            type="button"
            onClick={() => handleQuickPersona("admin@shieldnet.local", "Admin@123")}
            disabled={isLoading}
            className="flex flex-col text-left p-2.5 rounded-xl border transition-all hover:border-emerald-500/50 hover:bg-emerald-500/5 group cursor-pointer"
            style={{
              backgroundColor: "color-mix(in srgb, var(--color-base) 60%, transparent)",
              borderColor: "var(--color-border)",
            }}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wider">Level 5</span>
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 group-hover:scale-125 transition-transform" />
            </div>
            <div className="text-xs font-semibold text-[var(--color-text-primary)] mt-1">CISO Admin</div>
            <div className="text-[10px] text-[var(--color-text-muted)] truncate font-mono">admin@shieldnet.local</div>
          </button>

          {/* Persona 2: SOC Threat Hunter */}
          <button
            type="button"
            onClick={() => handleQuickPersona("analyst@shieldnet.local", "Analyst@123")}
            disabled={isLoading}
            className="flex flex-col text-left p-2.5 rounded-xl border transition-all hover:border-blue-500/50 hover:bg-blue-500/5 group cursor-pointer"
            style={{
              backgroundColor: "color-mix(in srgb, var(--color-base) 60%, transparent)",
              borderColor: "var(--color-border)",
            }}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-blue-400 uppercase tracking-wider">Level 3</span>
              <span className="h-1.5 w-1.5 rounded-full bg-blue-400 group-hover:scale-125 transition-transform" />
            </div>
            <div className="text-xs font-semibold text-[var(--color-text-primary)] mt-1">SOC Threat Hunter</div>
            <div className="text-[10px] text-[var(--color-text-muted)] truncate font-mono">analyst@shieldnet.local</div>
          </button>

          {/* Persona 3: Forensic Auditor */}
          <button
            type="button"
            onClick={() => handleQuickPersona("auditor@shieldnet.local", "Auditor@123")}
            disabled={isLoading}
            className="flex flex-col text-left p-2.5 rounded-xl border transition-all hover:border-amber-500/50 hover:bg-amber-500/5 group cursor-pointer"
            style={{
              backgroundColor: "color-mix(in srgb, var(--color-base) 60%, transparent)",
              borderColor: "var(--color-border)",
            }}
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wider">Level 4</span>
              <span className="h-1.5 w-1.5 rounded-full bg-amber-400 group-hover:scale-125 transition-transform" />
            </div>
            <div className="text-xs font-semibold text-[var(--color-text-primary)] mt-1">Forensic Auditor</div>
            <div className="text-[10px] text-[var(--color-text-muted)] truncate font-mono">auditor@shieldnet.local</div>
          </button>
        </div>
      </div>

      <div className="text-center">
        <button
          type="button"
          onClick={onSwitchMode}
          className="text-xs text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1 cursor-pointer"
        >
          <span>Need a new defense profile? Register New Operator</span>
          <ChevronRight size={13} />
        </button>
      </div>
    </div>
  );
}

// -----------------------------------------------------------------------------
// SIGN UP / NEW ENROLLMENT COMPONENT
// -----------------------------------------------------------------------------
function SignupForm({ onSwitchMode }: { onSwitchMode: () => void }) {
  const { signup, isLoading, targetPath, setTargetPath } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [displayName, setDisplayName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("SecOps_Analyst");
  const [department, setDepartment] = useState("NTRO Advanced Threat Unit");
  const [errorMsg, setErrorMsg] = useState("");

  const handlePostAuthRedirect = () => {
    if (targetPath) {
      const dest = targetPath;
      setTargetPath(null);
      navigate(dest);
    } else if (
      location.pathname === "/" ||
      location.pathname === "/about" ||
      location.pathname === "/architecture"
    ) {
      navigate("/dashboard");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");

    if (!displayName.trim() || !username.trim() || !password.trim()) {
      setErrorMsg("All mandatory fields must be completed.");
      return;
    }

    if (password.length < 6) {
      setErrorMsg("Password must be at least 6 characters for defense clearance compliance.");
      return;
    }

    try {
      await signup({
        username: username.trim().toLowerCase(),
        password: password.trim(),
        display_name: displayName.trim(),
        role,
        department: department.trim(),
      });
      handlePostAuthRedirect();
    } catch (err: any) {
      setErrorMsg(err?.message || "Registration failed. Username may already exist.");
    }
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-1">
            Officer / Operator Name *
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-muted)]">
              <User size={14} />
            </div>
            <input
              type="text"
              required
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="e.g. Capt. Vikram Batra"
              className="w-full rounded-xl border pl-9 pr-3 py-2 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)]"
              style={{
                backgroundColor: "var(--color-base, #0a0e17)",
                borderColor: "var(--color-border, #1f2937)",
              }}
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-1">
            Defense Email / Call-Sign *
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-muted)]">
              <UserCheck size={14} />
            </div>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. vikram@shieldnet.gov.in"
              className="w-full rounded-xl border pl-9 pr-3 py-2 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)] font-mono"
              style={{
                backgroundColor: "var(--color-base, #0a0e17)",
                borderColor: "var(--color-border, #1f2937)",
              }}
            />
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-1">
            Password (PBKDF2-HMAC-SHA256) *
          </label>
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-muted)]">
              <Lock size={14} />
            </div>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Min 6 characters"
              className="w-full rounded-xl border pl-9 pr-3 py-2 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)] font-mono"
              style={{
                backgroundColor: "var(--color-base, #0a0e17)",
                borderColor: "var(--color-border, #1f2937)",
              }}
            />
          </div>
        </div>

        <div>
          <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-1">
            Clearance Tier &amp; Role *
          </label>
          <select
            value={role}
            onChange={(e) => setRole(e.target.value)}
            className="w-full rounded-xl border px-3 py-2 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)]"
            style={{
              backgroundColor: "var(--color-base, #0a0e17)",
              borderColor: "var(--color-border, #1f2937)",
            }}
          >
            <option value="SecOps_Analyst">Level 3 - SecOps Analyst (Threat Hunter)</option>
            <option value="Forensic_Auditor">Level 4 - Forensic Auditor (Chain of Custody)</option>
            <option value="CISO_Admin">Level 5 - CISO Admin (Sovereign Authority)</option>
          </select>
        </div>
      </div>

      <div>
        <label className="block text-xs font-semibold uppercase tracking-wider text-[var(--color-text-secondary)] mb-1">
          Assigned Department / Command Unit
        </label>
        <div className="relative">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none text-[var(--color-text-muted)]">
            <Building size={14} />
          </div>
          <input
            type="text"
            value={department}
            onChange={(e) => setDepartment(e.target.value)}
            placeholder="e.g. NTRO Central SOC or Defence Cyber Agency (DCA)"
            className="w-full rounded-xl border pl-9 pr-3 py-2 text-xs text-[var(--color-text-primary)] outline-none transition-all focus:border-[var(--color-accent)]"
            style={{
              backgroundColor: "var(--color-base, #0a0e17)",
              borderColor: "var(--color-border, #1f2937)",
            }}
          />
        </div>
      </div>

      {errorMsg && (
        <div className="flex items-center gap-2 p-3 rounded-xl border border-rose-500/30 bg-rose-950/20 text-xs text-rose-300">
          <AlertTriangle size={15} className="shrink-0 text-rose-400" />
          <span>{errorMsg}</span>
        </div>
      )}

      <button
        type="submit"
        disabled={isLoading}
        className="w-full flex items-center justify-center gap-2 py-3 rounded-xl text-xs font-bold uppercase tracking-wider text-black transition-all shadow-lg hover:opacity-95 disabled:opacity-50 cursor-pointer"
        style={{
          background: "linear-gradient(135deg, #10b981 0%, #34d399 50%, #059669 100%)",
          boxShadow: "0 0 20px rgba(16, 185, 129, 0.35)",
        }}
      >
        {isLoading ? (
          <>
            <div className="h-4 w-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
            <span>Enrolling Defense Officer...</span>
          </>
        ) : (
          <>
            <UserPlus size={15} />
            <span>Enroll Operator &amp; Issue OAuth2 Token</span>
          </>
        )}
      </button>

      <div className="text-center pt-1">
        <button
          type="button"
          onClick={onSwitchMode}
          className="text-xs text-[var(--color-text-secondary)] hover:text-cyan-400 transition-colors cursor-pointer"
        >
          Already enrolled? <span className="text-cyan-400 underline underline-offset-2">Switch to Sign In</span>
        </button>
      </div>
    </form>
  );
}
