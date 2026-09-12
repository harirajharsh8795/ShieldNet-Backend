import { create } from "zustand";
import type { Ingestion } from "../data/types";

interface AppState {
  activeIngestion: Ingestion | null;
  selectedPredictionId: string | null;
  isExplainPanelOpen: boolean;
  setActiveIngestion: (ingestion: Ingestion | null) => void;
  openExplainPanel: (predictionId: string) => void;
  closeExplainPanel: () => void;
}

export const useAppStore = create<AppState>((set) => ({
  activeIngestion: null,
  selectedPredictionId: null,
  isExplainPanelOpen: false,
  setActiveIngestion: (ingestion) => set({ activeIngestion: ingestion }),
  openExplainPanel: (predictionId) =>
    set({ selectedPredictionId: predictionId, isExplainPanelOpen: true }),
  closeExplainPanel: () => set({ isExplainPanelOpen: false }),
}));
