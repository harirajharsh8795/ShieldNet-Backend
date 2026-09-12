import { Link } from "react-router-dom";
import { Database } from "lucide-react";
import type { Ingestion } from "../data/types";

interface DatasetSelectorProps {
  ingestion: Ingestion | null;
}

export function DatasetSelector({ ingestion }: DatasetSelectorProps) {
  if (!ingestion) {
    return (
      <Link
        to="/"
        className="inline-flex items-center gap-2 rounded-md border border-dashed px-3 py-1.5 font-mono text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text-primary)]"
        style={{ borderColor: "var(--color-border)" }}
      >
        <Database size={13} />
        No dataset loaded
      </Link>
    );
  }

  return (
    <Link
      to="/"
      className="inline-flex items-center gap-2 rounded-md border px-3 py-1.5 font-mono text-xs text-[var(--color-text-primary)] transition-colors hover:border-[var(--color-accent)]"
      style={{ borderColor: "var(--color-border)" }}
      title="Change data source"
    >
      <Database size={13} style={{ color: "var(--color-accent)" }} />
      {ingestion.datasetName}
    </Link>
  );
}
