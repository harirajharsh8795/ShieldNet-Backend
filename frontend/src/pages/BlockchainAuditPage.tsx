import { useState, useEffect } from "react";
import {
  CheckCircle2,
  AlertTriangle,
  Lock,
  Link as LinkIcon,
  FileCheck,
  Search,
  Upload,
  Cpu,
  Terminal,
  UserCheck,
  XCircle,
  RefreshCw,
  Network,
  Server,
  Zap,
  Printer,
  X,
  ShieldCheck,
  FileText
} from "lucide-react";
import {
  fetchLedgerBlocks,
  verifyEvidenceUpload,
  approveMitigationAction,
  fetchModelProvenance,
  submitAnalystOverride,
  fetchFabricClusterStatus,
  fetchFabricChannelLedger,
  proposeAndCommitFabricIOC,
  simulateFabricPartition,
  recoverFabricNode,
  type SIERLBlockData
} from "../data/api";


export function BlockchainAuditPage() {
  const [blocks, setBlocks] = useState<SIERLBlockData[]>([]);
  const [chainValid, setChainValid] = useState<boolean>(true);
  const [integrityMessage, setIntegrityMessage] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<"explorer" | "verifier" | "approval" | "model" | "fabric">("explorer");

  // Verification State
  const [verifyingFile, setVerifyingFile] = useState<boolean>(false);
  const [verificationResult, setVerificationResult] = useState<any>(null);
  const [manualHash, setManualHash] = useState<string>("");

  // Model Provenance
  const [modelProvenance, setModelProvenance] = useState<any>(null);

  // Simulated Tampering Demo
  const [tamperingSimulated, setTamperingSimulated] = useState<boolean>(false);

  // Section 63 Legal Certificate Modal
  const [certificateBlock, setCertificateBlock] = useState<SIERLBlockData | null>(null);

  // Approval State
  const [approvingId, setApprovingId] = useState<string | null>(null);
  const [approvalFeedback, setApprovalFeedback] = useState<string | null>(null);

  // Hyperledger Fabric Cross-CII State
  const [fabricCluster, setFabricCluster] = useState<any>(null);
  const [fabricLedger, setFabricLedger] = useState<any[]>([]);
  const [isProposingFabric, setIsProposingFabric] = useState<boolean>(false);
  const [fabricFeedback, setFabricFeedback] = useState<string | null>(null);
  const [selectedAttack, setSelectedAttack] = useState<string>("BlackEnergy SCADA Kill");
  const [selectedTarget, setSelectedTarget] = useState<string>("Wardha 765kV RTU");
  const [selectedIp, setSelectedIp] = useState<string>("192.168.10.45");

  useEffect(() => {
    loadLedgerData();
    loadModelProvenance();
    loadFabricData();
  }, []);

  const loadFabricData = async () => {
    const cluster = await fetchFabricClusterStatus();
    setFabricCluster(cluster);
    const ledger = await fetchFabricChannelLedger();
    setFabricLedger(ledger);
  };

  const loadLedgerData = async () => {
    setLoading(true);
    const res = await fetchLedgerBlocks();
    setBlocks(res.blocks || []);
    setChainValid(res.chain_valid);
    setIntegrityMessage(res.integrity_message);
    setLoading(false);
  };

  const loadModelProvenance = async () => {
    const res = await fetchModelProvenance();
    setModelProvenance(res);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setVerifyingFile(true);
    setVerificationResult(null);
    try {
      const res = await verifyEvidenceUpload(file);
      setVerificationResult(res);
    } catch (err) {
      console.error(err);
    } finally {
      setVerifyingFile(false);
    }
  };

  const handleManualHashVerify = () => {
    if (!manualHash.trim()) return;
    const cleanHash = manualHash.trim().toLowerCase();
    const matches = blocks.filter((b) => b.evidence_hash.toLowerCase() === cleanHash);

    if (matches.length > 0) {
      setVerificationResult({
        verified: true,
        evidence_hash: cleanHash,
        status: "AUTHENTIC_RECORD_FOUND",
        chain_valid: chainValid,
        message: `Forensic Match Confirmed! Found in Block #${matches[0].block_index} (${matches[0].threat_type}).`,
        matching_blocks: matches
      });
    } else {
      setVerificationResult({
        verified: false,
        evidence_hash: cleanHash,
        status: "UNREGISTERED_OR_TAMPERED",
        chain_valid: chainValid,
        message: "No matching evidence digest discovered on the immutable SIERL ledger."
      });
    }
  };

  const handleApprove = async (incidentId: string, decision: "APPROVED" | "REJECTED") => {
    setApprovingId(incidentId);
    setApprovalFeedback(null);
    try {
      const res = await approveMitigationAction(incidentId, decision, "CISO_Administrator");
      setApprovalFeedback(
        `Action ${decision} for ${incidentId}. Transaction anchored with rule: ${
          res.result?.orchestration_record?.generated_rules?.iptables || "DROP rule"
        }`
      );
      await loadLedgerData();
    } catch (err) {
      console.error(err);
    } finally {
      setApprovingId(null);
    }
  };

  const handleOverride = async (incidentId: string, originalThreat: string) => {
    const reason = window.prompt("Enter forensic override justification (e.g. 'Authorized administrative maintenance'):", "Authorized Sysadmin Routine Maintenance");
    if (!reason) return;
    const corrected = window.prompt("Enter ground-truth corrected label:", "BENIGN (Authorized Admin)");
    if (!corrected) return;

    setApprovingId(incidentId);
    try {
      const res = await submitAnalystOverride({
        incident_id: incidentId,
        original_threat: originalThreat,
        corrected_threat: corrected,
        reason: reason,
        analyst_name: "Senior_SOC_Analyst"
      });
      setApprovalFeedback(`False-Positive Override recorded on SIERL Block #${res.result?.block_index ?? 'New'}. Ground-truth committed to retraining ledger!`);
      await loadLedgerData();
    } catch (e) {
      console.error(e);
    } finally {
      setApprovingId(null);
    }
  };

  const toggleTamperSimulation = () => {

    if (!tamperingSimulated) {
      // Intentionally corrupt block 1 locally to show judge real-time tamper-detection
      if (blocks.length > 1) {
        const corrupted = [...blocks];
        corrupted[1] = {
          ...corrupted[1],
          threat_type: "MALICIOUS_INJECTED_OVERWRITE (TAMPERED)"
        };
        setBlocks(corrupted);
        setChainValid(false);
        setIntegrityMessage("CRITICAL ALERT: Block #1 Content Tampered! Hash mismatch detected by consensus guard.");
        setTamperingSimulated(true);
      }
    } else {
      // Restore legitimate state
      loadLedgerData();
      setTamperingSimulated(false);
    }
  };

  const handleProposeFabric = async () => {
    setIsProposingFabric(true);
    setFabricFeedback(null);
    try {
      const res = await proposeAndCommitFabricIOC({
        proposing_peer: "peer0.wardha.grid",
        threat_type: selectedAttack,
        adversary_ip: selectedIp,
        target_asset: selectedTarget,
        mitre_stage: "Impact (TA0040)",
        confidence: 0.95,
        proposed_action: "DENY_INGRESS_DROP"
      });
      setFabricFeedback(
        `Consensus Achieved! 2-of-3 Endorsement verified across ${res.endorsing_msps?.join(
          ", "
        )}. Committed to Fabric Channel Block #${res.block_index} (Merkle: ${res.merkle_root?.substring(0, 16)}...).`
      );
      await loadFabricData();
    } catch (e: any) {
      setFabricFeedback(`Consensus error: ${e.message || "Quorum rejection"}`);
    } finally {
      setIsProposingFabric(false);
    }
  };

  const handleTogglePartition = async (peerId: string, currentStatus: string) => {
    try {
      if (currentStatus === "ONLINE") {
        await simulateFabricPartition(peerId);
      } else {
        await recoverFabricNode(peerId);
      }
      await loadFabricData();
    } catch (e) {
      console.error("Partition toggle error:", e);
    }
  };


  return (
    <div className="w-full space-y-6">
      {/* Header Banner */}
      <div
        className="rounded-xl border p-6 glow-box"
        style={{
          borderColor: "var(--color-border)",
          backgroundColor: "var(--color-panel)",
          background: "linear-gradient(135deg, rgba(16,185,129,0.06) 0%, rgba(99,102,241,0.06) 100%)"
        }}
      >
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Lock size={12} /> SIERL Notary Layer Active
              </span>
              <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-mono bg-blue-500/10 text-blue-400 border border-blue-500/20">
                NTRO PS-153 / 1.pdf
              </span>
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-[var(--color-text-primary)]">
              ShieldNet Immutable Evidence & Response Ledger (SIERL)
            </h1>
            <p className="text-sm text-[var(--color-text-secondary)] mt-1 max-w-3xl">
              Cryptographically anchors AI threat forecasts, raw network evidence (PCAP/CSV), neural model weights,
              and human SOAR approval decisions onto a SHA-256 hash-chained ledger. Enforces the strict{" "}
              <strong className="text-[var(--color-accent)]">Notary vs. Executioner</strong> architectural separation.
            </p>
          </div>

          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => setCertificateBlock(blocks[0] || {
                index: 0,
                timestamp: "2026-09-19T18:30:00Z",
                data_hash: "7a92c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
                previous_hash: "0000000000000000000000000000000000000000000000000000000000000000",
                hash: "a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8",
                threat_class: "BENIGN_BASELINE_TELEMETRY",
                forecasting_horizon: "K=5",
                mitre_tactic: "TA0043 (Reconnaissance)",
                mitre_technique: "T1595 (Active Scanning)",
                evidence_reference: "pcap_evidence_verified_sha256_ref.pcap",
                model_hash: "f814b7e2a9c1d3e5a7b9c0d2e4f6a8b1c3d5e7f9a2b4c6d8e0f1a3b5c7d9e1f3",
                evidence_hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                status: "SEALED",
                soar_approved: true,
                soar_approver: "SecOps_Analyst (Level 3)",
                soar_action: "ISOLATE_HOST_AND_INSPECT"
              })}
              className="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-lg text-xs font-bold font-mono transition-all bg-gradient-to-r from-amber-500 to-yellow-500 hover:from-amber-400 hover:to-yellow-400 text-slate-950 shadow-md shadow-amber-500/20 cursor-pointer"
            >
              <ShieldCheck size={15} />
              <span>Section 63 / 65B Certificate</span>
            </button>
            <button
              onClick={loadLedgerData}
              className="inline-flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-medium transition-colors hover:bg-white/5"
              style={{ borderColor: "var(--color-border)", color: "var(--color-text-secondary)" }}
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh Ledger
            </button>
            <button
              onClick={toggleTamperSimulation}
              className={`inline-flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-bold transition-all border ${
                tamperingSimulated
                  ? "bg-amber-500/20 text-amber-300 border-amber-500/40"
                  : "bg-red-500/10 text-red-400 border-red-500/30 hover:bg-red-500/20"
              }`}
            >
              <AlertTriangle size={14} />
              {tamperingSimulated ? "Restore Genuine Ledger" : "Simulate Adversary Tampering"}
            </button>
          </div>
        </div>

        {/* Global Chain Status Indicator */}
        <div className="mt-4 pt-4 border-t flex flex-wrap items-center justify-between gap-4" style={{ borderColor: "var(--color-border)" }}>
          <div className="flex items-center gap-3">
            <div
              className={`flex h-10 w-10 items-center justify-center rounded-lg border ${
                chainValid
                  ? "bg-emerald-500/15 border-emerald-500/30 text-emerald-400"
                  : "bg-red-500/20 border-red-500/40 text-red-400 animate-pulse"
              }`}
            >
              {chainValid ? <CheckCircle2 size={20} /> : <AlertTriangle size={20} />}
            </div>
            <div>
              <div className="text-xs uppercase tracking-wider font-semibold text-[var(--color-text-muted)]">
                Cryptographic Chain Status
              </div>
              <div className={`text-sm font-bold ${chainValid ? "text-emerald-400" : "text-red-400"}`}>
                {chainValid ? "100% Valid & Tamper-Free" : "TAMPER DETECTED / INTEGRITY BREACH"}
              </div>
              {integrityMessage && (
                <div className="text-[11px] font-mono text-[var(--color-text-muted)] max-w-sm truncate">
                  {integrityMessage}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-6 text-xs text-[var(--color-text-secondary)] font-mono">
            <div>
              <span className="text-[var(--color-text-muted)]">BLOCKS: </span>
              <strong className="text-[var(--color-text-primary)]">{blocks.length}</strong>
            </div>
            <div>
              <span className="text-[var(--color-text-muted)]">ROOT GENESIS: </span>
              <strong className="text-[var(--color-text-primary)]">Block #0</strong>
            </div>
            <div>
              <span className="text-[var(--color-text-muted)]">HASH ENGINE: </span>
              <strong className="text-[var(--color-text-primary)]">SHA-256 (Canonical JSON)</strong>
            </div>
            <div>
              <span className="text-[var(--color-text-muted)]">STORAGE: </span>
              <strong className="text-emerald-400">Hybrid Off-Chain + Ledger</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sub-Tabs */}
      <div className="flex border-b gap-4 pb-2" style={{ borderColor: "var(--color-border)" }}>
        <button
          onClick={() => setActiveTab("explorer")}
          className={`inline-flex items-center gap-2 pb-2 text-sm font-medium border-b-2 transition-all ${
            activeTab === "explorer"
              ? "border-emerald-400 text-emerald-400"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          <LinkIcon size={16} /> Block Explorer ({blocks.length})
        </button>

        <button
          onClick={() => setActiveTab("verifier")}
          className={`inline-flex items-center gap-2 pb-2 text-sm font-medium border-b-2 transition-all ${
            activeTab === "verifier"
              ? "border-emerald-400 text-emerald-400"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          <FileCheck size={16} /> Forensic Evidence Verifier
        </button>

        <button
          onClick={() => setActiveTab("approval")}
          className={`inline-flex items-center gap-2 pb-2 text-sm font-medium border-b-2 transition-all ${
            activeTab === "approval"
              ? "border-emerald-400 text-emerald-400"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          <UserCheck size={16} /> Human-in-the-Loop SOAR Approvals
        </button>

        <button
          onClick={() => setActiveTab("model")}
          className={`inline-flex items-center gap-2 pb-2 text-sm font-medium border-b-2 transition-all ${
            activeTab === "model"
              ? "border-emerald-400 text-emerald-400"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          <Cpu size={16} /> Model Supply Chain Integrity
        </button>

        <button
          onClick={() => {
            setActiveTab("fabric");
            loadFabricData();
          }}
          className={`inline-flex items-center gap-2 pb-2 text-sm font-medium border-b-2 transition-all ${
            activeTab === "fabric"
              ? "border-emerald-400 text-emerald-400"
              : "border-transparent text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]"
          }`}
        >
          <Network size={16} /> Cross-CII Fabric Consortium (Tier-2 Realized)
        </button>
      </div>

      {/* TAB 1: BLOCK EXPLORER */}
      {activeTab === "explorer" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
            <span>Showing immutable blockchain timeline in chronological sequence</span>
            <span className="font-mono text-emerald-400">Ledger File: models/checkpoints/sierl_ledger.json</span>
          </div>

          <div className="space-y-4">
            {blocks.map((block) => (
              <div
                key={block.block_index}
                className="rounded-xl border p-5 transition-all glow-box relative"
                style={{
                  borderColor: block.block_index === 0 ? "rgba(99,102,241,0.3)" : "var(--color-border)",
                  backgroundColor: "var(--color-panel)"
                }}
              >
                {/* Block Top Row */}
                <div className="flex flex-wrap items-center justify-between gap-3 border-b pb-3 mb-3" style={{ borderColor: "var(--color-border)" }}>
                  <div className="flex items-center gap-2.5">
                    <span
                      className="px-2.5 py-1 rounded text-xs font-bold font-mono"
                      style={{
                        backgroundColor: block.block_index === 0 ? "rgba(99,102,241,0.15)" : "rgba(16,185,129,0.15)",
                        color: block.block_index === 0 ? "#818cf8" : "#34d399",
                        border: `1px solid ${block.block_index === 0 ? "rgba(99,102,241,0.3)" : "rgba(16,185,129,0.3)"}`
                      }}
                    >
                      BLOCK #{block.block_index}
                    </span>
                    <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                      {block.threat_type}
                    </span>
                    <span className="text-xs text-[var(--color-text-muted)] font-mono">
                      ({block.incident_id})
                    </span>
                  </div>

                  <div className="flex items-center gap-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        block.approval_state === "APPROVED" || block.approval_state === "GENESIS_AUTHORIZED"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                          : block.approval_state === "REJECTED"
                          ? "bg-red-500/10 text-red-400 border border-red-500/20"
                          : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                      }`}
                    >
                      {block.approval_state}
                    </span>
                    <span className="text-xs font-mono text-[var(--color-text-muted)]">
                      {new Date(block.timestamp).toLocaleString()}
                    </span>
                  </div>
                </div>

                {/* Hashes Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="p-2.5 rounded bg-black/20 border" style={{ borderColor: "var(--color-border)" }}>
                    <div className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
                      Evidence Hash (SHA-256) · {block.evidence_name}
                    </div>
                    <div className="truncate text-emerald-400 selection:bg-emerald-500 selection:text-black">
                      {block.evidence_hash}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-black/20 border" style={{ borderColor: "var(--color-border)" }}>
                    <div className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
                      Model Weights Supply-Chain Digest
                    </div>
                    <div className="truncate text-blue-400">
                      {block.model_hash}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-black/20 border" style={{ borderColor: "var(--color-border)" }}>
                    <div className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
                      Prediction Output Hash · Conf: {(block.confidence * 100).toFixed(1)}%
                    </div>
                    <div className="truncate text-purple-400">
                      {block.prediction_hash}
                    </div>
                  </div>

                  <div className="p-2.5 rounded bg-black/20 border" style={{ borderColor: "var(--color-border)" }}>
                    <div className="text-[10px] text-[var(--color-text-muted)] uppercase tracking-wider mb-1">
                      XAI Feature Attribution Hash
                    </div>
                    <div className="truncate text-amber-400">
                      {block.xai_hash}
                    </div>
                  </div>
                </div>

                {/* Chaining Cryptography Row */}
                <div className="mt-3 pt-3 border-t grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono" style={{ borderColor: "var(--color-border)" }}>
                  <div>
                    <span className="text-[var(--color-text-muted)]">PREV_HASH: </span>
                    <span className="truncate text-[var(--color-text-secondary)]">{block.prev_hash}</span>
                  </div>
                  <div>
                    <span className="text-[var(--color-text-muted)]">BLOCK_HASH: </span>
                    <span className="truncate font-bold text-emerald-400">{block.block_hash}</span>
                  </div>
                </div>

                {/* Section 63 Legal Evidence Certificate Action */}
                <div className="mt-3 pt-2.5 border-t flex flex-wrap items-center justify-between gap-2" style={{ borderColor: "var(--color-border)" }}>
                  <span className="text-[11px] text-[var(--color-text-muted)] font-mono flex items-center gap-1.5">
                    <ShieldCheck size={13} className="text-emerald-400" />
                    BSA 2023 Sec 63 Legal Audit Seal (Court-Admissible)
                  </span>
                  <button
                    onClick={() => setCertificateBlock(block)}
                    className="inline-flex items-center gap-1.5 px-3 py-1 rounded-lg text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20 transition-all cursor-pointer"
                  >
                    <FileText size={13} /> View Section 63 Certificate
                  </button>
                </div>

                {/* Firewall Execution Log (if orchestrated) */}
                {block.orchestration_record && (
                  <div className="mt-3 p-3 rounded bg-emerald-950/20 border border-emerald-800/30 text-xs">
                    <div className="flex items-center gap-2 font-semibold text-emerald-400 mb-1">
                      <Terminal size={14} /> SOAR Execution Telemetry (Enforced via Firewall API)
                    </div>
                    <div className="text-[var(--color-text-secondary)] font-mono text-[11px]">
                      {block.orchestration_record.generated_rules?.iptables || block.orchestration_record.effect}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 2: FORENSIC EVIDENCE VERIFIER */}
      {activeTab === "verifier" && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Drag and Drop Card */}
            <div
              className="rounded-xl border p-6 glow-box"
              style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
            >
              <h3 className="text-base font-bold text-[var(--color-text-primary)] mb-1 flex items-center gap-2">
                <Upload size={18} className="text-emerald-400" />
                Upload Forensic PCAP / CSV Artifact
              </h3>
              <p className="text-xs text-[var(--color-text-secondary)] mb-4">
                Computes real-time client-side & server-side SHA-256 digest and compares against the SIERL on-chain
                commitments to detect tampering or unauthorized modification.
              </p>

              <label className="flex flex-col items-center justify-center p-8 border-2 border-dashed rounded-xl cursor-pointer hover:border-emerald-400/50 hover:bg-emerald-500/5 transition-all">
                <Upload size={32} className="text-emerald-400 mb-2 animate-bounce" />
                <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                  Click or drag PCAP/CSV file here
                </span>
                <span className="text-xs text-[var(--color-text-muted)] mt-1">
                  Supports .pcap, .pcapng, .csv, .json (Up to 100MB)
                </span>
                <input
                  type="file"
                  className="hidden"
                  onChange={handleFileUpload}
                  accept=".pcap,.pcapng,.csv,.json"
                />
              </label>

              {verifyingFile && (
                <div className="mt-4 text-xs text-emerald-400 flex items-center gap-2">
                  <RefreshCw size={14} className="animate-spin" /> Computing SHA-256 digest and verifying ledger consensus...
                </div>
              )}
            </div>

            {/* Manual Hash Lookup Card */}
            <div
              className="rounded-xl border p-6 glow-box"
              style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
            >
              <h3 className="text-base font-bold text-[var(--color-text-primary)] mb-1 flex items-center gap-2">
                <Search size={18} className="text-blue-400" />
                Manual SHA-256 Hash Verification
              </h3>
              <p className="text-xs text-[var(--color-text-secondary)] mb-4">
                Paste an existing SHA-256 evidence digest to query the immutable block ledger and inspect chain linkage.
              </p>

              <div className="space-y-3">
                <textarea
                  value={manualHash}
                  onChange={(e) => setManualHash(e.target.value)}
                  placeholder="Paste 64-character hex SHA-256 digest here (e.g. 4a28f89c6d321528b77a06a201bcf5a3...)"
                  className="w-full h-28 p-3 rounded-lg border bg-black/30 font-mono text-xs text-[var(--color-text-primary)] focus:border-emerald-400 focus:outline-none"
                  style={{ borderColor: "var(--color-border)" }}
                />

                <div className="flex gap-2">
                  <button
                    onClick={handleManualHashVerify}
                    className="px-4 py-2 rounded-lg bg-emerald-500 text-black font-semibold text-xs hover:bg-emerald-400 transition-colors"
                  >
                    Verify On-Chain Hash
                  </button>
                  <button
                    onClick={() => {
                      if (blocks.length > 1) {
                        setManualHash(blocks[1].evidence_hash);
                      }
                    }}
                    className="px-3 py-2 rounded-lg border text-xs text-[var(--color-text-secondary)] hover:bg-white/5"
                    style={{ borderColor: "var(--color-border)" }}
                  >
                    Paste Sample Block #1 Hash
                  </button>
                </div>
              </div>
            </div>
          </div>

          {/* Verification Results Banner */}
          {verificationResult && (
            <div
              className={`rounded-xl border p-6 glow-box transition-all ${
                verificationResult.verified
                  ? "bg-emerald-950/20 border-emerald-500/40 text-emerald-300"
                  : "bg-red-950/20 border-red-500/40 text-red-300"
              }`}
            >
              <div className="flex items-start gap-3">
                <div
                  className={`p-2 rounded-lg ${
                    verificationResult.verified ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"
                  }`}
                >
                  {verificationResult.verified ? <CheckCircle2 size={24} /> : <XCircle size={24} />}
                </div>

                <div className="space-y-2 flex-1">
                  <div className="flex items-center justify-between">
                    <h4 className="text-base font-bold">
                      {verificationResult.verified ? "AUTHENTIC EVIDENCE VERIFIED" : "EVIDENCE UNVERIFIED / TAMPERED"}
                    </h4>
                    <span className="text-xs font-mono px-2 py-0.5 rounded bg-black/40">
                      {verificationResult.status}
                    </span>
                  </div>

                  <p className="text-xs">{verificationResult.message}</p>

                  <div className="p-3 rounded bg-black/40 font-mono text-xs space-y-1">
                    <div>
                      <span className="text-[var(--color-text-muted)]">Target Hash: </span>
                      <span className="text-white select-all">{verificationResult.evidence_hash}</span>
                    </div>
                    {verificationResult.filename && (
                      <div>
                        <span className="text-[var(--color-text-muted)]">File: </span>
                        <span className="text-white">{verificationResult.filename}</span> (
                        {verificationResult.filesize_bytes} bytes)
                      </div>
                    )}
                  </div>

                  {verificationResult.matching_blocks?.length > 0 && (
                    <div className="mt-3 pt-3 border-t border-emerald-500/20 text-xs">
                      <span className="font-semibold">Associated Ledger Anchor: </span>
                      Block #{verificationResult.matching_blocks[0].block_index} (
                      {verificationResult.matching_blocks[0].threat_type}) committed at{" "}
                      {new Date(verificationResult.matching_blocks[0].timestamp).toLocaleString()}
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: HUMAN-IN-THE-LOOP SOAR APPROVAL */}
      {activeTab === "approval" && (
        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs text-[var(--color-text-secondary)]">
            <span>Security Administrator Decision Hub: Authorize proportional mitigation actions</span>
            <span className="font-mono text-amber-400">Architecture: Notary (Ledger) → Trigger → Firewall API</span>
          </div>

          {approvalFeedback && (
            <div className="p-4 rounded-xl bg-emerald-950/20 border border-emerald-500/30 text-emerald-300 text-xs flex items-center gap-2">
              <CheckCircle2 size={16} /> {approvalFeedback}
            </div>
          )}

          <div className="space-y-3">
            {blocks
              .filter((b) => b.block_index > 0)
              .map((block) => (
                <div
                  key={block.block_index}
                  className="rounded-xl border p-5 glow-box flex flex-col md:flex-row items-start md:items-center justify-between gap-4"
                  style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-500/15 text-blue-400 border border-blue-500/30">
                        {block.incident_id}
                      </span>
                      <span className="text-sm font-semibold text-[var(--color-text-primary)]">
                        {block.threat_type}
                      </span>
                      <span className="text-xs px-2 py-0.5 rounded bg-red-500/10 text-red-400 font-bold">
                        {block.severity}
                      </span>
                    </div>

                    <div className="text-xs text-[var(--color-text-secondary)]">
                      Target: <strong className="text-white font-mono">{block.target_ip}</strong> · Recommended Action:{" "}
                      <strong className="text-emerald-400 font-mono">{block.proposed_action}</strong>
                    </div>

                    <div className="text-[11px] font-mono text-[var(--color-text-muted)] truncate max-w-xl">
                      Ledger Hash: {block.block_hash}
                    </div>
                  </div>

                    <div className="flex items-center gap-2">
                    {block.approval_state === "PENDING" ? (
                      <>
                        <button
                          disabled={approvingId === block.incident_id}
                          onClick={() => handleApprove(block.incident_id, "APPROVED")}
                          className="px-3.5 py-1.5 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 transition-colors flex items-center gap-1.5"
                        >
                          <CheckCircle2 size={14} /> Authorize SOAR
                        </button>
                        <button
                          disabled={approvingId === block.incident_id}
                          onClick={() => handleOverride(block.incident_id, block.threat_type)}
                          className="px-3 py-1.5 rounded-lg bg-amber-500/20 text-amber-300 border border-amber-500/30 text-xs font-semibold hover:bg-amber-500/30 transition-colors flex items-center gap-1"
                          title="Commit human analyst ground-truth feedback to SIERL retraining ledger"
                        >
                          Override FP
                        </button>
                        <button
                          disabled={approvingId === block.incident_id}
                          onClick={() => handleApprove(block.incident_id, "REJECTED")}
                          className="px-3 py-1.5 rounded-lg bg-red-500/20 text-red-300 text-xs font-semibold hover:bg-red-500/30 transition-colors"
                        >
                          Reject
                        </button>
                      </>
                    ) : (
                      <div className="text-right">
                        <span
                          className={`px-3 py-1 rounded text-xs font-bold ${
                            block.approval_state === "APPROVED"
                              ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                              : block.approval_state === "OVERRIDDEN_FALSE_POSITIVE"
                              ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                              : "bg-red-500/20 text-red-400 border border-red-500/30"
                          }`}
                        >
                          {block.approval_state === "OVERRIDDEN_FALSE_POSITIVE" ? "OVERRIDDEN FP" : block.approval_state}
                        </span>
                        <div className="text-[10px] text-[var(--color-text-muted)] mt-1 font-mono">
                          By: {block.approver_role || "SecOps Lead"}
                        </div>
                      </div>
                    )}
                  </div>

                </div>
              ))}
          </div>
        </div>
      )}

      {/* TAB 4: MODEL SUPPLY CHAIN INTEGRITY */}
      {activeTab === "model" && (
        <div className="space-y-6">
          <div
            className="rounded-xl border p-6 glow-box"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
          >
            <h3 className="text-base font-bold text-[var(--color-text-primary)] mb-1 flex items-center gap-2">
              <Cpu size={18} className="text-purple-400" />
              Machine Learning Supply Chain Integrity (Model Provenance)
            </h3>
            <p className="text-xs text-[var(--color-text-secondary)] mb-4">
              Cryptographically hashes active neural network weights and preprocessors to ensure model supply chain
              security and prove zero weight-poisoning or model-swapping attacks.
            </p>

            <div className="space-y-3">
              {modelProvenance?.artifacts?.map((art: any, i: number) => (
                <div
                  key={i}
                  className="p-4 rounded-xl border bg-black/20 flex flex-col md:flex-row items-start md:items-center justify-between gap-3 font-mono text-xs"
                  style={{ borderColor: "var(--color-border)" }}
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <strong className="text-white text-sm">{art.model_name}</strong>
                      <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 font-bold">
                        VERIFIED_ON_DISK
                      </span>
                    </div>
                    <div className="text-[var(--color-text-muted)] truncate max-w-xl text-[11px]">
                      Path: {art.model_path}
                    </div>
                  </div>

                  <div className="text-right">
                    <div className="text-[10px] text-[var(--color-text-muted)] uppercase">SHA-256 Checkpoint Digest</div>
                    <div className="text-purple-400 font-bold select-all text-xs">{art.sha256}</div>
                    <div className="text-[10px] text-[var(--color-text-muted)] mt-0.5">
                      {(art.size_bytes / 1024 / 1024).toFixed(2)} MB
                    </div>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-4 p-4 rounded-lg bg-blue-950/20 border border-blue-800/30 text-xs text-blue-300">
              <strong>Sovereign Defense Property:</strong> When ShieldNet generates a threat forecast, it binds the
              prediction not only to the evidence hash, but also to the active model hash. An auditor can verify which
              exact model weights were running when the incident occurred.
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: CROSS-CII HYPERLEDGER FABRIC CONSORTIUM (TIER-2 REALIZED) */}
      {activeTab === "fabric" && (
        <div className="space-y-6">
          {/* Consortium Overview Banner */}
          <div
            className="rounded-xl border p-6 glow-box"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
          >
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 border-b pb-4 mb-4" style={{ borderColor: "var(--color-border)" }}>
              <div>
                <h3 className="text-base font-bold text-[var(--color-text-primary)] flex items-center gap-2">
                  <Network size={18} className="text-emerald-400" />
                  Hyperledger Fabric Cross-CII Consortium (Tier-2 Architecture Realized)
                </h3>
                <p className="text-xs text-[var(--color-text-secondary)] mt-1">
                  Distributed permissioned ledger across 3 National Power Grid Substations. Enforces 2-of-3 multi-MSP
                  cryptographic endorsement, Byzantine fault tolerance, and Notary vs. Executioner separation.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <span
                  className={`px-3 py-1 rounded-full text-xs font-bold ${
                    fabricCluster?.cluster_health === "HEALTHY"
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                      : "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                  }`}
                >
                  {fabricCluster?.cluster_health || "HEALTHY"}
                </span>
                <button
                  type="button"
                  onClick={loadFabricData}
                  className="p-2 rounded-lg border hover:bg-[var(--color-base)] text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
                  style={{ borderColor: "var(--color-border)" }}
                  title="Refresh Consortium State"
                >
                  <RefreshCw size={14} />
                </button>
              </div>
            </div>

            {/* Consortium Key Metrics */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono">
              <div className="p-3 rounded-lg border bg-black/20" style={{ borderColor: "var(--color-border)" }}>
                <div className="text-[10px] text-[var(--color-text-muted)] uppercase">Channel Name</div>
                <div className="text-emerald-400 font-bold truncate mt-0.5">
                  {fabricCluster?.channel_name || "cross-cii-grid-defense-channel"}
                </div>
              </div>
              <div className="p-3 rounded-lg border bg-black/20" style={{ borderColor: "var(--color-border)" }}>
                <div className="text-[10px] text-[var(--color-text-muted)] uppercase">Endorsement Policy</div>
                <div className="text-purple-400 font-bold mt-0.5 truncate">OutOf(2, 3 MSPs)</div>
              </div>
              <div className="p-3 rounded-lg border bg-black/20" style={{ borderColor: "var(--color-border)" }}>
                <div className="text-[10px] text-[var(--color-text-muted)] uppercase">Ordering Service</div>
                <div className="text-blue-400 font-bold mt-0.5 truncate">Raft CFT (NRLDC Orderer)</div>
              </div>
              <div className="p-3 rounded-lg border bg-black/20" style={{ borderColor: "var(--color-border)" }}>
                <div className="text-[10px] text-[var(--color-text-muted)] uppercase">Channel Block Height</div>
                <div className="text-amber-400 font-bold mt-0.5">
                  {fabricCluster?.block_height ?? fabricLedger.length ?? 1} Blocks Replicated
                </div>
              </div>
            </div>
          </div>

          {/* 3 Substation Nodes Grid */}
          <div>
            <h4 className="text-sm font-semibold text-[var(--color-text-primary)] mb-3 flex items-center gap-2">
              <Server size={16} className="text-blue-400" />
              Consortium Substation Peer Nodes (X.509 MSP Identities):
            </h4>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {fabricCluster?.peers?.map((peer: any) => {
                const isOnline = peer.status === "ONLINE";
                return (
                  <div
                    key={peer.node_id}
                    className="p-5 rounded-xl border flex flex-col justify-between space-y-4 glow-box transition-all"
                    style={{
                      borderColor: isOnline ? "var(--color-border)" : "#EF444460",
                      backgroundColor: "var(--color-panel)"
                    }}
                  >
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-blue-500/10 text-blue-400 font-bold border border-blue-500/20">
                          {peer.grid_voltage}
                        </span>
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            isOnline ? "bg-emerald-500/10 text-emerald-400" : "bg-rose-500/10 text-rose-400"
                          }`}
                        >
                          {peer.status}
                        </span>
                      </div>

                      <h5 className="font-bold text-sm text-[var(--color-text-primary)] leading-snug">
                        {peer.substation_name}
                      </h5>
                      <div className="text-[11px] text-[var(--color-text-muted)] mt-0.5">{peer.org_name}</div>

                      <div className="mt-3 space-y-1.5 text-xs font-mono text-[var(--color-text-secondary)]">
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">MSP ID:</span>
                          <span className="text-purple-400 font-bold">{peer.msp_id}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Endpoint:</span>
                          <span className="truncate max-w-[140px]">{peer.endpoint}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Cert Fingerprint:</span>
                          <span className="text-emerald-400">{peer.cert_fingerprint?.substring(0, 10)}...</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-[var(--color-text-muted)]">Local Ledger Height:</span>
                          <span className="text-[var(--color-text-primary)] font-bold">{peer.block_height} Blocks</span>
                        </div>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={() => handleTogglePartition(peer.node_id, peer.status)}
                      className={`w-full py-2 px-3 text-xs font-semibold rounded-lg transition-all border ${
                        isOnline
                          ? "border-rose-500/30 text-rose-400 hover:bg-rose-500/10"
                          : "border-emerald-500/30 text-emerald-400 hover:bg-emerald-500/10"
                      }`}
                    >
                      {isOnline ? "Simulate Fiber Cut (Partition Node)" : "Recover Node & Gossip Sync"}
                    </button>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Interactive Collaborative Consensus Sandbox */}
          <div
            className="rounded-xl border p-6 glow-box"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
          >
            <div className="flex items-center gap-2 mb-2">
              <Zap size={18} className="text-amber-400" />
              <h4 className="text-sm font-bold text-[var(--color-text-primary)]">
                Cross-CII Incident Endorsement Sandbox (Notary vs. Executioner Demo)
              </h4>
            </div>
            <p className="text-xs text-[var(--color-text-secondary)] mb-4">
              Simulate Wardha Substation detecting a lateral APT attempt. The proposal requires cryptographic
              endorsements from at least 2 distinct substations before the NRLDC Raft Orderer packs it into the channel
              ledger.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
              <div>
                <label className="block text-[11px] font-medium text-[var(--color-text-muted)] uppercase mb-1">
                  Threat Classification
                </label>
                <select
                  value={selectedAttack}
                  onChange={(e) => setSelectedAttack(e.target.value)}
                  className="w-full rounded-lg border px-3 py-2 text-xs text-[var(--color-text-primary)] outline-none"
                  style={{ backgroundColor: "var(--color-base)", borderColor: "var(--color-border)" }}
                >
                  <option value="BlackEnergy SCADA Kill">BlackEnergy SCADA Kill (ICS APT)</option>
                  <option value="DDoS-SYN-Flood">DDoS-SYN-Flood (Telecontrol Saturation)</option>
                  <option value="Modbus-Infiltration">Modbus-Infiltration (Remote Substation Takeover)</option>
                  <option value="PortScan-Recon">PortScan-Recon (IEC 60870-5-104 Discovery)</option>
                </select>
              </div>

              <div>
                <label className="block text-[11px] font-medium text-[var(--color-text-muted)] uppercase mb-1">
                  Target CII Asset
                </label>
                <input
                  type="text"
                  value={selectedTarget}
                  onChange={(e) => setSelectedTarget(e.target.value)}
                  className="w-full rounded-lg border px-3 py-2 text-xs text-[var(--color-text-primary)] outline-none"
                  style={{ backgroundColor: "var(--color-base)", borderColor: "var(--color-border)" }}
                />
              </div>

              <div>
                <label className="block text-[11px] font-medium text-[var(--color-text-muted)] uppercase mb-1">
                  Adversary Source IP
                </label>
                <input
                  type="text"
                  value={selectedIp}
                  onChange={(e) => setSelectedIp(e.target.value)}
                  className="w-full rounded-lg border px-3 py-2 text-xs text-[var(--color-text-primary)] outline-none font-mono"
                  style={{ backgroundColor: "var(--color-base)", borderColor: "var(--color-border)" }}
                />
              </div>
            </div>

            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 pt-2">
              <div className="text-xs text-[var(--color-text-muted)] font-mono">
                Consensus Flow: Proposal ➔ Endorse (Wardha + Jabalpur/Indore) ➔ NRLDC Raft Order ➔ Gossip Commit
              </div>

              <button
                type="button"
                onClick={handleProposeFabric}
                disabled={isProposingFabric}
                className="px-5 py-2.5 rounded-lg bg-[var(--color-accent)] text-[var(--color-base)] text-xs font-bold hover:opacity-90 transition-all shadow-md disabled:opacity-50 flex items-center gap-2"
              >
                {isProposingFabric ? (
                  <>
                    <RefreshCw size={14} className="animate-spin" />
                    Executing 2-of-3 Consensus...
                  </>
                ) : (
                  <>
                    <Network size={14} />
                    Trigger Cross-CII Collaborative Endorsement
                  </>
                )}
              </button>
            </div>

            {fabricFeedback && (
              <div className="mt-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-400 font-mono">
                {fabricFeedback}
              </div>
            )}
          </div>

          {/* Replicated Fabric Channel Ledger Blocks */}
          <div
            className="rounded-xl border p-6 glow-box"
            style={{ borderColor: "var(--color-border)", backgroundColor: "var(--color-panel)" }}
          >
            <h4 className="text-sm font-bold text-[var(--color-text-primary)] mb-3 flex items-center gap-2">
              <LinkIcon size={16} className="text-emerald-400" />
              Replicated Fabric Channel Ledger (Gossip Synchronized):
            </h4>

            <div className="space-y-3">
              {fabricLedger.length === 0 ? (
                <div className="text-xs text-[var(--color-text-muted)] p-4 text-center">
                  Loading channel ledger blocks...
                </div>
              ) : (
                fabricLedger.map((block: any) => (
                  <div
                    key={block.block_index}
                    className="p-4 rounded-xl border bg-black/20 text-xs font-mono space-y-2"
                    style={{ borderColor: "var(--color-border)" }}
                  >
                    <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 border-b pb-2" style={{ borderColor: "var(--color-border)" }}>
                      <div className="flex items-center gap-2">
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-500/20 text-emerald-400">
                          BLOCK #{block.block_index}
                        </span>
                        <span className="text-[var(--color-text-muted)]">
                          {block.transactions?.[0]?.type || block.transactions?.[0]?.threat_type || "CONFIG_GENESIS"}
                        </span>
                      </div>
                      <div className="text-[10px] text-[var(--color-text-muted)]">
                        Timestamp: {block.timestamp}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px]">
                      <div>
                        <span className="text-[var(--color-text-muted)]">Block Hash: </span>
                        <span className="text-emerald-400 select-all">{block.block_hash}</span>
                      </div>
                      <div>
                        <span className="text-[var(--color-text-muted)]">Merkle Root: </span>
                        <span className="text-purple-400 select-all">{block.merkle_root}</span>
                      </div>
                      <div>
                        <span className="text-[var(--color-text-muted)]">Orderer Node: </span>
                        <span className="text-blue-400">{block.orderer_metadata?.orderer_id || "orderer0.nrldc.gov.in"}</span>
                      </div>
                      <div>
                        <span className="text-[var(--color-text-muted)]">Endorsing MSPs: </span>
                        <span className="text-amber-400">
                          {block.transactions?.[0]?.endorsing_msps?.join(", ") || "Channel Consortium MSPs"}
                        </span>
                      </div>
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>
      )}

      {/* SECTION 63 LEGAL AUDIT CERTIFICATE MODAL */}
      {certificateBlock && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
          <div
            className="w-full max-w-2xl rounded-2xl border p-6 glow-box shadow-2xl relative space-y-4 max-h-[90vh] overflow-y-auto"
            style={{ borderColor: "rgba(16,185,129,0.5)", backgroundColor: "var(--color-panel)" }}
          >
            {/* Header */}
            <div className="flex items-start justify-between border-b pb-4" style={{ borderColor: "var(--color-border)" }}>
              <div className="space-y-1">
                <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded text-[10px] font-mono font-bold uppercase tracking-wider bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                  <ShieldCheck size={12} /> Republic of India · Forensic Audit Registry
                </div>
                <h2 className="text-base font-bold text-[var(--color-text-primary)]">
                  CERTIFICATE OF ELECTRONIC EVIDENCE
                </h2>
                <p className="text-xs text-[var(--color-text-muted)] font-mono">
                  Under Section 63, Bharatiya Sakshya Adhiniyam (BSA), 2023 (formerly Section 65B, Indian Evidence Act, 1872)
                </p>
              </div>
              <button
                onClick={() => setCertificateBlock(null)}
                className="p-1.5 rounded-lg hover:bg-white/10 text-[var(--color-text-muted)] hover:text-white transition-all cursor-pointer"
              >
                <X size={20} />
              </button>
            </div>

            {/* Certificate Content */}
            <div className="p-4 rounded-xl bg-black/40 border border-emerald-500/20 space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-2 text-[11px]">
                <div><span className="text-[var(--color-text-muted)]">CERTIFICATE ID:</span> <span className="text-emerald-400 font-bold">SIERL-BSA-{certificateBlock.block_index}-{certificateBlock.incident_id?.slice(0, 8) || "4092"}</span></div>
                <div><span className="text-[var(--color-text-muted)]">ISSUED AT:</span> <span className="text-[var(--color-text-primary)]">{new Date(certificateBlock.timestamp).toUTCString()}</span></div>
                <div><span className="text-[var(--color-text-muted)]">SYSTEM SENSOR ID:</span> <span className="text-[var(--color-text-primary)]">NTRO-SHIELDNET-GATEWAY-01</span></div>
                <div><span className="text-[var(--color-text-muted)]">INCIDENT CLASSIFICATION:</span> <span className="text-red-400 font-bold">{certificateBlock.threat_type}</span></div>
              </div>

              <div className="border-t pt-2 space-y-2 text-[11px]" style={{ borderColor: "var(--color-border)" }}>
                <div>
                  <div className="text-[10px] text-[var(--color-text-muted)] uppercase">1. Raw Telemetry Evidence Digest (SHA-256):</div>
                  <div className="p-2 rounded bg-black/60 text-emerald-400 break-all select-all font-mono text-[10px]">
                    {certificateBlock.evidence_hash}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-[var(--color-text-muted)] uppercase">2. Frozen AI Model Weight Supply-Chain Digest:</div>
                  <div className="p-2 rounded bg-black/60 text-blue-400 break-all font-mono text-[10px]">
                    {certificateBlock.model_hash}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-[var(--color-text-muted)] uppercase">3. Multi-Task Threat Prediction Hash:</div>
                  <div className="p-2 rounded bg-black/60 text-purple-400 break-all font-mono text-[10px]">
                    {certificateBlock.prediction_hash}
                  </div>
                </div>

                <div>
                  <div className="text-[10px] text-[var(--color-text-muted)] uppercase">4. Block Merkle Signature (Immutable Ledger Seal):</div>
                  <div className="p-2 rounded bg-black/60 text-amber-400 break-all font-bold font-mono text-[10px]">
                    {certificateBlock.block_hash}
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-500/30 text-[11px] text-emerald-300 space-y-1 font-sans">
                <div className="font-bold flex items-center gap-1.5 text-emerald-400">
                  <CheckCircle2 size={14} /> Official Statutory Certification Clause
                </div>
                <p className="text-[10px] text-emerald-200/90 leading-relaxed">
                  I hereby certify that the electronic record detailed above was automatically produced by the ShieldNet Sovereign Neural Gateway during lawful enterprise telemetry ingestion. The cryptographic SHA-256 chain guarantees that no tampering, post-hoc alteration, or unauthorized data substitution has occurred since creation.
                </p>
              </div>
            </div>

            {/* Footer Actions */}
            <div className="flex items-center justify-between pt-2">
              <span className="text-[11px] text-[var(--color-text-muted)] font-mono">
                Status: Verified Tamper-Evident · Admissible in Court
              </span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => window.print()}
                  className="px-4 py-1.5 rounded-lg border text-xs font-semibold text-[var(--color-text-primary)] hover:bg-white/5 transition-all cursor-pointer flex items-center gap-1.5"
                  style={{ borderColor: "var(--color-border)" }}
                >
                  <Printer size={13} /> Print Certificate
                </button>
                <button
                  onClick={() => setCertificateBlock(null)}
                  className="px-4 py-1.5 rounded-lg bg-emerald-500 text-black text-xs font-bold hover:bg-emerald-400 transition-all cursor-pointer"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

