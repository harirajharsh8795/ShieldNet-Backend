import { useEffect, useState } from "react";
import { ShieldCheck, Cpu } from "lucide-react";
import { checkBackendHealth } from "../data/api";

export function OfflineStatusBadge() {
  const [online, setOnline] = useState(true);

  useEffect(() => {
    checkBackendHealth().then((res) => {
      setOnline(res.status !== "offline_mock");
    });
  }, []);

  return (
    <div
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-mono uppercase tracking-wider"
      style={{
        borderColor: online ? "var(--color-normal)" : "var(--color-accent)",
        color: online ? "var(--color-normal)" : "var(--color-accent)",
        backgroundColor: online
          ? "color-mix(in srgb, var(--color-normal) 10%, transparent)"
          : "color-mix(in srgb, var(--color-accent) 10%, transparent)",
      }}
      title={online ? "Connected to Local PyTorch World Model (FastAPI :8000)" : "Running in 100% Offline Standalone Mode"}
    >
      {online ? <Cpu size={12} strokeWidth={2.5} /> : <ShieldCheck size={12} strokeWidth={2.5} />}
      <span>{online ? "Local AI Model Active" : "Offline Ready (C4)"}</span>
    </div>
  );
}
