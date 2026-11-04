/** Case-scoped navigation targets shared by the sidebar, command palette and `g x` shortcuts. */
const LAST_CASE_KEY = "veritas.lastCase";

export interface CaseSection {
  key: string;
  shortcut: string | null;
  label: string;
  path: (caseId: string) => string;
}

export const CASE_SECTIONS: CaseSection[] = [
  { key: "dashboard", shortcut: "g d", label: "Dashboard", path: (c) => `/cases/${c}` },
  { key: "evidence", shortcut: "g e", label: "Evidence", path: (c) => `/cases/${c}/evidence` },
  { key: "timeline", shortcut: "g t", label: "Timeline", path: (c) => `/cases/${c}/timeline` },
  { key: "memory", shortcut: null, label: "Memory", path: (c) => `/cases/${c}/memory` },
  { key: "graph", shortcut: null, label: "Graphs", path: (c) => `/cases/${c}/graph` },
  { key: "findings", shortcut: "g f", label: "Findings", path: (c) => `/cases/${c}/findings` },
  { key: "iocs", shortcut: "g i", label: "IOCs", path: (c) => `/cases/${c}/iocs` },
  { key: "reports", shortcut: "g r", label: "Reports", path: (c) => `/cases/${c}/reports` },
  { key: "custody", shortcut: "g l", label: "Custody", path: (c) => `/cases/${c}/custody` },
];

export function caseIdFromPath(pathname: string | null): string | null {
  const m = /^\/cases\/([^/]+)/.exec(pathname ?? "");
  return m?.[1] ? decodeURIComponent(m[1]) : null;
}

export function activeSection(pathname: string | null): string | null {
  const m = /^\/cases\/[^/]+(?:\/([^/]+))?/.exec(pathname ?? "");
  if (!m) return null;
  return m[1] ?? "dashboard";
}

export function rememberCase(caseId: string, storage: Storage | null = safeSession()): void {
  storage?.setItem(LAST_CASE_KEY, caseId);
}

export function lastCase(storage: Storage | null = safeSession()): string | null {
  return storage?.getItem(LAST_CASE_KEY) ?? null;
}

export function forgetCase(storage: Storage | null = safeSession()): void {
  storage?.removeItem(LAST_CASE_KEY);
}

function safeSession(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.sessionStorage;
  } catch {
    return null;
  }
}

/** Resolve a `g x` sequence to a path, using the current or last-visited case. */
export function shortcutTarget(sequence: string, caseId: string | null): string | null {
  if (sequence === "g c") return "/cases";
  const section = CASE_SECTIONS.find((s) => s.shortcut === sequence);
  if (!section) return null;
  return caseId ? section.path(encodeURIComponent(caseId)) : "/cases";
}
