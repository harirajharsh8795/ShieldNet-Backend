
import { useState } from "react";
import { Download, Check } from "lucide-react";
import { exportResults } from "../data/api";

interface ExportButtonProps {
  ingestionId: string;
}

export function ExportButton({ ingestionId }: ExportButtonProps) {
  const [state, setState] = useState<"idle" | "exporting" | "done">("idle");

  async function handleExport() {
    setState("exporting");
    const data = await exportResults(ingestionId);
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `shieldnet-export-${ingestionId}.json`;
    a.click();
    URL.revokeObjectURL(url);
    setState("done");
    setTimeout(() => setState("idle"), 1800);
  }

  return (
    <button
      onClick={handleExport}
      disabled={state === "exporting"}
      className="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 text-xs font-medium transition-colors hover:bg-[var(--color-panel-raised)] disabled:opacity-60"
      style={{ borderColor: "var(--color-border)", color: "var(--color-text-primary)" }}
    >
      {state === "done" ? (
        <>
          <Check size={13} style={{ color: "var(--color-normal)" }} />
          Exported
        </>
      ) : (
        <>
          <Download size={13} />
          {state === "exporting" ? "Exporting…" : "Export results"}
        </>
      )}
    </button>
  );
}
