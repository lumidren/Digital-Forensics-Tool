/**
 * Timeline filter model and its two serializations: the API search body and the URL query string
 * (so a filtered view can be bookmarked, shared, saved and restored).
 */
import type { SearchBody, TimelineEvent } from "./types";

export interface TimelineFilters {
  text: string;
  start_ns: number | null;
  end_ns: number | null;
  data_types: string[];
  hosts: string[];
  users: string[];
  evidence: string[];
  parsers: string[];
  attr_equals: Record<string, string>;
}

export const EMPTY_FILTERS: TimelineFilters = {
  text: "",
  start_ns: null,
  end_ns: null,
  data_types: [],
  hosts: [],
  users: [],
  evidence: [],
  parsers: [],
  attr_equals: {},
};

export type ListField = "data_types" | "hosts" | "users" | "evidence" | "parsers";

export const LIST_FIELDS: { field: ListField; param: string; label: string; column: string }[] = [
  { field: "data_types", param: "dt", label: "Data type", column: "data_type" },
  { field: "hosts", param: "host", label: "Host", column: "host" },
  { field: "users", param: "user", label: "User", column: "user" },
  { field: "evidence", param: "ev", label: "Evidence", column: "evidence_sha256" },
  { field: "parsers", param: "parser", label: "Parser", column: "parser" },
];

/** Event column -> filter list it pivots into. */
export const PIVOT_COLUMNS: Record<string, ListField> = {
  data_type: "data_types",
  host: "hosts",
  user: "users",
  evidence_sha256: "evidence",
  parser: "parsers",
};

export interface SearchOptions {
  limit?: number;
  offset?: number;
  unmask?: boolean;
  descending?: boolean;
}

export function toSearchBody(f: TimelineFilters, o: SearchOptions = {}): SearchBody {
  const body: SearchBody = {};
  const text = f.text.trim();
  if (text) body.text = text;
  if (f.start_ns !== null) body.start_ns = f.start_ns;
  if (f.end_ns !== null) body.end_ns = f.end_ns;
  for (const { field } of LIST_FIELDS) {
    if (f[field].length) body[field] = [...f[field]];
  }
  if (Object.keys(f.attr_equals).length) body.attr_equals = { ...f.attr_equals };
  if (o.limit !== undefined) body.limit = o.limit;
  if (o.offset !== undefined) body.offset = o.offset;
  if (o.unmask) body.unmask = true;
  if (o.descending) body.descending = true;
  return body;
}

function parseIntParam(v: string | null): number | null {
  if (v === null || !/^-?\d+$/.test(v)) return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

export function filtersToParams(f: TimelineFilters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.text.trim()) p.set("q", f.text.trim());
  if (f.start_ns !== null) p.set("from", String(f.start_ns));
  if (f.end_ns !== null) p.set("to", String(f.end_ns));
  for (const { field, param } of LIST_FIELDS) {
    for (const v of f[field]) p.append(param, v);
  }
  for (const [k, v] of Object.entries(f.attr_equals).sort(([a], [b]) => a.localeCompare(b))) {
    p.append("attr", `${k}=${v}`);
  }
  return p;
}

export function filtersFromParams(p: URLSearchParams): TimelineFilters {
  const f: TimelineFilters = {
    ...EMPTY_FILTERS,
    text: p.get("q") ?? "",
    start_ns: parseIntParam(p.get("from")),
    end_ns: parseIntParam(p.get("to")),
    attr_equals: {},
  };
  for (const { field, param } of LIST_FIELDS) {
    f[field] = [...new Set(p.getAll(param).filter(Boolean))];
  }
  for (const pair of p.getAll("attr")) {
    const i = pair.indexOf("=");
    if (i > 0) f.attr_equals[pair.slice(0, i)] = pair.slice(i + 1);
  }
  return f;
}

/** Saved views store the filter object; accept anything and keep only well-formed fields. */
export function filtersFromUnknown(q: Record<string, unknown>): TimelineFilters {
  const strList = (v: unknown): string[] =>
    Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
  const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
  const attrs: Record<string, string> = {};
  if (q.attr_equals && typeof q.attr_equals === "object") {
    for (const [k, v] of Object.entries(q.attr_equals as Record<string, unknown>)) {
      if (typeof v === "string") attrs[k] = v;
    }
  }
  return {
    text: typeof q.text === "string" ? q.text : "",
    start_ns: num(q.start_ns),
    end_ns: num(q.end_ns),
    data_types: strList(q.data_types),
    hosts: strList(q.hosts),
    users: strList(q.users),
    evidence: strList(q.evidence),
    parsers: strList(q.parsers),
    attr_equals: attrs,
  };
}

/**
 * Add a pivot filter. `column` is an event column (data_type, host, ...) or `attrs.<key>`.
 * Returns the same object when nothing changes.
 */
export function addPivot(f: TimelineFilters, column: string, value: string): TimelineFilters {
  if (column.startsWith("attrs.")) {
    const key = column.slice("attrs.".length);
    if (!key || f.attr_equals[key] === value) return f;
    return { ...f, attr_equals: { ...f.attr_equals, [key]: value } };
  }
  const field = PIVOT_COLUMNS[column];
  if (!field || f[field].includes(value)) return f;
  return { ...f, [field]: [...f[field], value] };
}

export interface FilterChip {
  key: string;
  label: string;
  value: string;
  remove: (f: TimelineFilters) => TimelineFilters;
}

export function filterChips(f: TimelineFilters, fmtNs: (ns: number) => string): FilterChip[] {
  const chips: FilterChip[] = [];
  if (f.text.trim())
    chips.push({ key: "q", label: "Text", value: f.text.trim(), remove: (x) => ({ ...x, text: "" }) });
  if (f.start_ns !== null) {
    chips.push({
      key: "from",
      label: "From",
      value: fmtNs(f.start_ns),
      remove: (x) => ({ ...x, start_ns: null }),
    });
  }
  if (f.end_ns !== null) {
    chips.push({
      key: "to",
      label: "Before",
      value: fmtNs(f.end_ns),
      remove: (x) => ({ ...x, end_ns: null }),
    });
  }
  for (const { field, label } of LIST_FIELDS) {
    for (const v of f[field]) {
      chips.push({
        key: `${field}:${v}`,
        label,
        value: v,
        remove: (x) => ({ ...x, [field]: x[field].filter((y) => y !== v) }),
      });
    }
  }
  for (const [k, v] of Object.entries(f.attr_equals)) {
    chips.push({
      key: `attr:${k}`,
      label: k,
      value: v,
      remove: (x) => ({
        ...x,
        attr_equals: Object.fromEntries(Object.entries(x.attr_equals).filter(([key]) => key !== k)),
      }),
    });
  }
  return chips;
}

export function hasFilters(f: TimelineFilters): boolean {
  return filtersToParams(f).toString() !== "";
}

/** Values in an event that can be pivoted on, with their filter column. */
export function pivotableFields(e: TimelineEvent): { column: string; value: string }[] {
  const out: { column: string; value: string }[] = [{ column: "data_type", value: e.data_type }];
  if (e.host) out.push({ column: "host", value: e.host });
  if (e.user) out.push({ column: "user", value: e.user });
  if (e.parser) out.push({ column: "parser", value: e.parser });
  if (e.evidence_sha256) out.push({ column: "evidence_sha256", value: e.evidence_sha256 });
  return out;
}

/** Attribute values usable with `attr_equals` (scalars only; the API compares as text). */
export function attrFilterValue(v: unknown): string | null {
  if (typeof v === "string") return v;
  if (typeof v === "number" && Number.isFinite(v)) return String(v);
  if (typeof v === "boolean") return v ? "1" : "0";
  return null;
}
