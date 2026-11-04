/** Display formatting. Timestamps are integer nanoseconds since the Unix epoch, UTC. */
const NS_PER_MS = 1_000_000;

export function formatNs(ns: number | null | undefined): string {
  if (ns === null || ns === undefined || !Number.isFinite(ns)) return "—";
  const ms = Math.floor(ns / NS_PER_MS);
  const date = new Date(ms);
  if (Number.isNaN(date.getTime())) return "—";
  const micros = Math.floor((((ns % 1e9) + 1e9) % 1e9) / 1000);
  return `${date.toISOString().slice(0, 19)}.${String(micros).padStart(6, "0")}Z`;
}

export function formatNsShort(ns: number): string {
  return new Date(Math.floor(ns / NS_PER_MS)).toISOString().slice(0, 19).replace("T", " ");
}

/** Parse a datetime-local / ISO string (UTC assumed when no offset) to ns. */
export function isoToNs(text: string): number | null {
  const t = text.trim();
  if (!t) return null;
  const withZone = /([zZ]|[+-]\d\d:?\d\d)$/.test(t) ? t : `${t}Z`;
  const ms = Date.parse(withZone);
  return Number.isNaN(ms) ? null : ms * NS_PER_MS;
}

/** ns -> value for an <input type="datetime-local"> interpreted as UTC. */
export function nsToInput(ns: number | null): string {
  if (ns === null) return "";
  return new Date(Math.floor(ns / NS_PER_MS)).toISOString().slice(0, 19);
}

export function formatBytes(n: number): string {
  if (!Number.isFinite(n) || n < 0) return "—";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return i === 0 ? `${n} B` : `${v.toFixed(1)} ${units[i] ?? "B"}`;
}

export function formatDuration(ns: number): string {
  const s = ns / 1e9;
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${s / 60} min`;
  if (s < 86400) return `${s / 3600} h`;
  return `${s / 86400} d`;
}

export function shortHash(h: string | null | undefined, n = 12): string {
  if (!h) return "—";
  return h.length > n ? `${h.slice(0, n)}…` : h;
}

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : `${d.toISOString().slice(0, 19).replace("T", " ")}Z`;
}

export function formatPercent(fraction: number): string {
  const v = Math.max(0, Math.min(1, fraction));
  return `${Math.round(v * 100)}%`;
}

export function stringifyValue(v: unknown): string {
  if (v === null || v === undefined) return "";
  if (typeof v === "string") return v;
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return JSON.stringify(v);
}
