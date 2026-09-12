import { useState } from "react";
import { Download, Monitor, Globe, Terminal, CheckCircle2, Shield, Copy, Check, X, AlertTriangle } from "lucide-react";

interface DownloadAgentModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export function DownloadAgentModal({ isOpen, onClose }: DownloadAgentModalProps) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<"desktop" | "extension" | "cli">("desktop");

  if (!isOpen) return null;

  const quickCommand = "git clone https://github.com/harirajharsh8795/ShieldNet-Backend.git && cd ShieldNet-Backend && run_offline.bat";

  const handleCopy = () => {
    navigator.clipboard.writeText(quickCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="relative w-full max-w-2xl rounded-2xl border border-white/10 bg-[#0b1320] p-6 text-slate-100 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-white/10 pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400">
              <Download size={20} />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Deploy ShieldNet Defense Agents</h3>
              <p className="text-xs text-slate-400">Cross-Platform Host Agent, Browser Control Panel & Zero-Config CLI</p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 hover:bg-white/10 hover:text-white transition-colors"
          >
            <X size={18} />
          </button>
        </div>

        {/* Tab Selection */}
        <div className="mt-5 grid grid-cols-3 gap-2 rounded-xl bg-slate-900/60 p-1 border border-white/5">
          <button
            onClick={() => setActiveTab("desktop")}
            className={`flex items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-all ${
              activeTab === "desktop"
                ? "bg-cyan-500 text-slate-950 shadow-md"
                : "text-slate-400 hover:text-white hover:bg-white/5"
            }`}
          >
            <Monitor size={14} />
            Desktop Agent
          </button>
          <button
            onClick={() => setActiveTab("extension")}
            className={`flex items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-all ${
              activeTab === "extension"
                ? "bg-cyan-500 text-slate-950 shadow-md"
                : "text-slate-400 hover:text-white hover:bg-white/5"
            }`}
          >
            <Globe size={14} />
            Chrome Extension
          </button>
          <button
            onClick={() => setActiveTab("cli")}
            className={`flex items-center justify-center gap-2 rounded-lg py-2 text-xs font-semibold transition-all ${
              activeTab === "cli"
                ? "bg-cyan-500 text-slate-950 shadow-md"
                : "text-slate-400 hover:text-white hover:bg-white/5"
            }`}
          >
            <Terminal size={14} />
            Single-Line CLI
          </button>
        </div>

        {/* Tab Content */}
        <div className="mt-5 space-y-4">
          {activeTab === "desktop" && (
            <div className="space-y-3 rounded-xl border border-white/5 bg-slate-900/40 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="font-semibold text-white text-sm">Windows / Linux Native Desktop Agent</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Monitors network sockets via Npcap, executes AI threat rollouts, and generates firewall deny rules.
                  </p>
                </div>
                <span className="rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-[10px] font-bold text-emerald-400 border border-emerald-500/20">
                  C4 Air-Gap Compliant
                </span>
              </div>

              <div className="space-y-2 text-xs text-slate-300">
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={14} className="text-cyan-400 shrink-0" />
                  <span>Includes offline pre-trained 21.52M Champion World Model</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={14} className="text-cyan-400 shrink-0" />
                  <span>Direct iptables &amp; Windows Filtering Platform firewall actuation</span>
                </div>
                <div className="flex items-center gap-2">
                  <CheckCircle2 size={14} className="text-cyan-400 shrink-0" />
                  <span>Instant WhatsApp &amp; Email incident dispatch via Alert Sentinel</span>
                </div>
              </div>

              <div className="pt-2">
                <a
                  href="https://github.com/harirajharsh8795/ShieldNet-Backend/archive/refs/heads/main.zip"
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-center gap-2 w-full rounded-lg bg-gradient-to-r from-cyan-500 to-blue-600 px-4 py-2.5 text-xs font-bold text-slate-950 hover:brightness-110 transition-all shadow-lg"
                >
                  <Download size={14} />
                  Download Full Desktop Agent Package (.ZIP)
                </a>
                <p className="text-[10px] text-center text-slate-500 mt-2">
                  After extracting, simply run <code className="text-cyan-400">run_offline.bat</code> to start the agent.
                </p>
              </div>
            </div>
          )}

          {activeTab === "extension" && (
            <div className="space-y-3 rounded-xl border border-white/5 bg-slate-900/40 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="font-semibold text-white text-sm">ShieldNet Local Defense Browser Extension</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Manifest V3 control panel for Chrome, Edge, and Brave browsers.
                  </p>
                </div>
                <span className="rounded-full bg-blue-500/10 px-2.5 py-0.5 text-[10px] font-bold text-blue-400 border border-blue-500/20">
                  Manifest V3
                </span>
              </div>

              <ol className="list-decimal list-inside space-y-1.5 text-xs text-slate-300">
                <li>Download the unpacked extension ZIP package.</li>
                <li>Extract the folder to your computer.</li>
                <li>In Chrome, navigate to <code className="text-cyan-400">chrome://extensions</code> and enable <strong>Developer mode</strong>.</li>
                <li>Click <strong>Load unpacked</strong> and select the extracted folder.</li>
                <li>Pin ShieldNet to your browser toolbar for live health and status alerts.</li>
              </ol>

              <div className="pt-2">
                <a
                  href="https://github.com/harirajharsh8795/ShieldNet-Backend/tree/main/browser-extension"
                  target="_blank"
                  rel="noreferrer"
                  className="flex items-center justify-center gap-2 w-full rounded-lg bg-gradient-to-r from-blue-500 to-indigo-600 px-4 py-2.5 text-xs font-bold text-white hover:brightness-110 transition-all shadow-lg"
                >
                  <Download size={14} />
                  Download Browser Extension Package
                </a>
              </div>
            </div>
          )}

          {activeTab === "cli" && (
            <div className="space-y-3 rounded-xl border border-white/5 bg-slate-900/40 p-4">
              <div className="flex items-start justify-between">
                <div>
                  <h4 className="font-semibold text-white text-sm">One-Line Quick Setup for Evaluators</h4>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Clone, verify, and start both the backend daemon and local React dashboard with a single command.
                  </p>
                </div>
              </div>

              <div className="relative rounded-lg bg-black/80 p-3 font-mono text-[11px] text-emerald-400 border border-white/10">
                <p className="break-all">{quickCommand}</p>
                <button
                  onClick={handleCopy}
                  className="absolute right-2 top-2 rounded bg-white/10 p-1.5 text-slate-300 hover:bg-white/20 hover:text-white transition-colors"
                >
                  {copied ? <Check size={14} className="text-emerald-400" /> : <Copy size={14} />}
                </button>
              </div>

              <div className="flex items-center gap-2 rounded-lg bg-amber-500/10 p-2.5 text-[11px] text-amber-300 border border-amber-500/20">
                <AlertTriangle size={15} className="shrink-0 text-amber-400" />
                <span>Zero cloud configuration required. Runs completely offline on local CPU.</span>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="mt-5 flex items-center justify-between border-t border-white/10 pt-4 text-xs text-slate-400">
          <div className="flex items-center gap-2">
            <Shield size={14} className="text-cyan-400" />
            <span>National Technical Research Organisation · SIH 2026</span>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg bg-white/10 px-4 py-1.5 font-medium text-white hover:bg-white/20 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
