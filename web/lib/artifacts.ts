/** Artifact-type classification and helpers used by the specialized event renderers. */
import type { AttrValue } from "./types";

export type ViewerKind =
  | "evtx"
  | "prefetch"
  | "registry"
  | "lnk"
  | "browser"
  | "fs"
  | "usn"
  | "memory-process"
  | "memory-network"
  | "memory-injection"
  | "memory"
  | "network"
  | "cloud"
  | "generic";

const RULES: [RegExp, ViewerKind][] = [
  [/^windows:evtx?:record$/, "evtx"],
  [/^windows:prefetch/, "prefetch"],
  [/^windows:registry/, "registry"],
  [/^windows:(lnk|jump_list|shell_item)/, "lnk"],
  [/^(chrome|firefox|edge|safari|chromium|opera):/, "browser"],
  [/^fs:ntfs:usn/, "usn"],
  [/^fs:/, "fs"],
  [/^memory:process(:|$)/, "memory-process"],
  [/^memory:network/, "memory-network"],
  [/^memory:injection/, "memory-injection"],
  [/^memory:/, "memory"],
  [/^(network|zeek|pcap):/, "network"],
  [/^(aws|azure|gcp|m365|o365|google|okta|cloud):/, "cloud"],
];

export function viewerKind(dataType: string): ViewerKind {
  for (const [re, kind] of RULES) if (re.test(dataType)) return kind;
  return "generic";
}

export function pick(attrs: Record<string, AttrValue>, ...keys: string[]): AttrValue | undefined {
  for (const k of keys) {
    const v = attrs[k];
    if (v !== undefined && v !== null && v !== "") return v;
  }
  return undefined;
}

export function asRecord(v: AttrValue | undefined): Record<string, AttrValue> | null {
  return v && typeof v === "object" && !Array.isArray(v) ? v : null;
}

export function asList(v: AttrValue | undefined): AttrValue[] {
  return Array.isArray(v) ? v : v === undefined || v === null ? [] : [v];
}

export const TIME_FIELDS = ["crtime", "mtime", "ctime", "atime"] as const;
export type TimeField = (typeof TIME_FIELDS)[number];

export const TIME_FIELD_LABEL: Record<TimeField, string> = {
  crtime: "Created",
  mtime: "Modified",
  ctime: "MFT changed",
  atime: "Accessed",
};

export interface SiFnRow {
  field: TimeField;
  si: number | null;
  fn: number | null;
  /** Reasons this pair looks manipulated; empty when consistent. */
  flags: string[];
}

function nsValue(v: AttrValue | undefined): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && /^\d+$/.test(v)) return Number(v);
  return null;
}

/**
 * $STANDARD_INFORMATION vs $FILE_NAME comparison. Heuristics mirror the analytics module:
 * SI earlier than FN (SI is user-settable, FN is not), and SI with zero sub-second precision
 * while FN has a fractional part (typical of tools that set whole seconds).
 */
export function siFnComparison(attrs: Record<string, AttrValue>): SiFnRow[] {
  const rows: SiFnRow[] = [];
  for (const field of TIME_FIELDS) {
    const si = nsValue(pick(attrs, `si_${field}_ns`, `si_${field}`));
    const fn = nsValue(pick(attrs, `fn_${field}_ns`, `fn_${field}`));
    if (si === null && fn === null) continue;
    const flags: string[] = [];
    if (si !== null && fn !== null && si < fn) flags.push("SI earlier than FN");
    if (si !== null && fn !== null && si % 1e9 === 0 && fn % 1e9 !== 0)
      flags.push("SI has zero sub-second precision");
    rows.push({ field, si, fn, flags });
  }
  return rows;
}

export function timestompIndicators(attrs: Record<string, AttrValue>): string[] {
  const fromParser = asList(attrs.timestomp_indicators).map(String);
  const derived = siFnComparison(attrs).flatMap((r) =>
    r.flags.map((f) => `${TIME_FIELD_LABEL[r.field]}: ${f}`),
  );
  return [...new Set([...fromParser, ...derived])];
}

/** USN reason flags as a list (accepts `A|B`, `A, B` or an array). */
export function usnReasons(attrs: Record<string, AttrValue>): string[] {
  const v = pick(attrs, "update_reason_flags", "reason", "reasons");
  if (Array.isArray(v)) return v.map(String);
  if (typeof v === "string") return v.split(/[|,\s]+/).filter(Boolean);
  return [];
}

export const NOTABLE_USN = new Set([
  "FILE_DELETE",
  "RENAME_OLD_NAME",
  "RENAME_NEW_NAME",
  "FILE_CREATE",
  "DATA_OVERWRITE",
]);
