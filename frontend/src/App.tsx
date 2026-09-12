import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { ThemeProvider } from "./context/ThemeContext";
import { Layout } from "./components/Layout";
import { HomePage } from "./pages/HomePage";
import { AboutPage } from "./pages/AboutPage";
import { ArchitecturePage } from "./pages/ArchitecturePage";
import { DashboardPage } from "./pages/DashboardPage";
import { ExplainabilityPage } from "./pages/ExplainabilityPage";
import { ComparePage } from "./pages/ComparePage";

export default function App() {
  return (
    <ThemeProvider>
      <BrowserRouter>
        <Layout>
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/about" element={<AboutPage />} />
            <Route path="/architecture" element={<ArchitecturePage />} />

            <Route path="/explainability" element={<ExplainabilityPage />} />
            <Route path="/dashboard/explainability" element={<ExplainabilityPage />} />
            <Route path="/baseline" element={<ComparePage />} />
            <Route path="/dashboard/baseline" element={<ComparePage />} />

            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="/dashboard/live" element={<DashboardPage />} />
            <Route path="/dashboard/simulation" element={<DashboardPage />} />
            <Route path="/dashboard/alerts" element={<DashboardPage />} />
            <Route path="/dashboard/blockchain" element={<DashboardPage />} />

            <Route path="/upload" element={<Navigate to="/dashboard" replace />} />
            <Route path="/simulation" element={<Navigate to="/dashboard/simulation" replace />} />
            <Route path="/compare" element={<Navigate to="/dashboard/baseline" replace />} />
            <Route path="/alerts" element={<Navigate to="/dashboard/alerts" replace />} />
            <Route path="/blockchain" element={<Navigate to="/dashboard/blockchain" replace />} />

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </Layout>
      </BrowserRouter>
    </ThemeProvider>
  );
}
