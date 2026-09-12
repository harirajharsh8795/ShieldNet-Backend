# ShieldNet — Network Attack Forecasting Dashboard (Frontend)

Frontend-only build for **ShieldNet** (NTRO, Blockchain & Cybersecurity theme). This is the
UI/UX layer for a World Model-based network attack forecasting tool — there is no backend
here. Every screen reads through a single mock data layer behind a typed API interface, so
a real backend can be wired in later with no component changes.

## Setup

```bash
npm install
npm run dev
```

Open the printed local URL (typically `http://localhost:5173`).

```bash
npm run build     # production build → dist/
npm run preview   # preview the production build locally
```

No network access is required at any point — fonts are self-hosted (`@fontsource`), all
data comes from the mock layer, and there are no external CDN dependencies at runtime.

## What's real vs. mocked

**Real:** all UI, layout, routing, animation, chart rendering, and the typed data contracts.

**Mocked:** `src/data/mockData.ts` generates a believable sample timeline, flagged flows,
SHAP-style explanations, and model comparison metrics. `src/data/api.ts` wraps that data in
async functions shaped exactly like the real API (`/api/ingest`, `/api/predict/:id`, etc.),
each with a `// TODO(backend)` marking where a real `fetch` call goes. **Components only
ever import from `api.ts`** — never from `mockData.ts` directly — so swapping in a real
backend is a pure implementation swap inside that one file.

No ML, packet parsing, or model training logic is implemented or simulated beyond
plausible-looking numbers.

## Structure

```
src/
  data/
    types.ts        TypeScript interfaces mirroring the backend schema exactly
    mockData.ts      Generated sample data (the only file allowed to fabricate data)
    api.ts           Async functions components call — mock now, real fetch later
  store/
    useAppStore.ts   Zustand store: active ingestion, selected prediction, panel state
  components/        Reusable, typed UI components (see list below)
  pages/
    UploadPage.tsx        "/"            Data source selection + mocked processing
    SimulationPage.tsx    "/simulation"  Hero screen: timeline, K-step rollout, flows
    ComparePage.tsx       "/compare"     World Model vs. baseline metrics
    ArchitecturePage.tsx  "/architecture" Pipeline diagram + CII narrative
  App.tsx            Router + layout wiring
  index.css          Design tokens (Tailwind v4 @theme) + global styles
```

## Components

`DataSourceCard`, `ProbabilityTimeline`, `KStepProjection`, `MITREStageBadge`,
`FlaggedFlowsList`, `FlaggedFlowRow`, `ExplainabilityPanel`, `SHAPBarChart`,
`BaselineComparisonChart`, `PipelineDiagram`, `MetricCard`, `OfflineStatusBadge`,
`ConfidenceDecayIndicator`, `DatasetSelector`, `ExportButton`, `Layout` (persistent nav).

## Design system

Dark-mode command-center aesthetic, tokens defined once in `src/index.css`:

- Background `#0A0E17`, panels `#151B2B`
- Accent (AI/predictive elements only) `#22D3EE`
- Severity scale: normal `#34D399` → watch `#FACC15` → elevated `#FB923C` → critical `#F43F5E`
- MITRE ATT&CK stage colors: Recon `#818CF8`, Initial Access `#F472B6`,
  Lateral Movement `#FB923C`, C2 `#F43F5E`, Exfiltration `#DC2626`
- Type: JetBrains Mono for numbers/IPs/timestamps, Inter for everything else

**Signature visual:** the K-step forward-simulation panel on `/simulation` — bars fade in
opacity the further into the future they project, making confidence-decay visible rather
than implied. This is the one place the product's real thesis (forecast, not classify) is
made tangible in the UI.

## Accessibility / quality floor

- Visible focus rings (`:focus-visible`) throughout, including chart interaction points
- `prefers-reduced-motion` respected globally
- Responsive down to narrow viewports (sidebar layout collapses gracefully)
- Empty/loading states are written in the tool's own voice (e.g. "No flows flagged in this
  window"), not generic placeholders

## Known trade-offs

- Bundle is a single chunk (~240 KB gzipped); code-splitting by route would help if this
  grows further, not done here to keep the swap-in-a-backend surface small.
- Recharts is used for line/bar charts rather than raw D3/Plotly, per the tech-stack
  brief's "Recharts (or Plotly.js if you prefer richer interactivity)" allowance.

