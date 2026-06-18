import type { Severity } from "../types";

// Couleurs sémantiques par sévérité (texte + fond discret + bordure).
export const SEVERITY_STYLE: Record<Severity, string> = {
  Info: "text-sky-400 bg-sky-950/40 border-sky-900",
  Low: "text-emerald-400 bg-emerald-950/40 border-emerald-900",
  Medium: "text-amber-400 bg-amber-950/40 border-amber-900",
  High: "text-orange-400 bg-orange-950/40 border-orange-900",
  Critical: "text-red-400 bg-red-950/50 border-red-900",
};
