import { Sun, Moon } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export function ThemeToggle() {
  const { theme, toggleTheme } = useTheme();

  return (
    <button
      type="button"
      onClick={toggleTheme}
      aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
      className="relative inline-flex h-9 w-9 items-center justify-center rounded-md border transition-colors hover:opacity-90"
      style={{
        borderColor: "var(--color-border)",
        backgroundColor: "color-mix(in srgb, var(--color-panel) 80%, transparent)",
        color: "var(--color-text-primary)",
      }}
      title={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
    >
      {theme === "dark" ? (
        <Sun size={16} className="text-amber-400 transition-transform rotate-0 scale-100" />
      ) : (
        <Moon size={16} className="text-indigo-600 transition-transform rotate-0 scale-100" />
      )}
    </button>
  );
}
