/** Findings workspace helpers: filtering, grouping and parsing of free-text id lists. */
import type { Finding, FindingState } from "./types";
import { FINDING_STATES } from "./types";

export interface FindingFilter {
  severity: string;
  rule: string;
  technique: string;
}

export const NO_FINDING_FILTER: FindingFilter = { severity: "", rule: "", technique: "" };

export function filterFindings(items: Finding[], f: FindingFilter): Finding[] {
  const tech = f.technique.trim().toUpperCase();
  return items.filter(
    (x) =>
      (!f.severity || x.severity === f.severity) &&
      (!f.rule || x.rule === f.rule) &&
      (!tech || x.attack_techniques.some((t) => t.toUpperCase().startsWith(tech))),
  );
}

export function groupByState(items: Finding[]): { state: FindingState; items: Finding[] }[] {
  return FINDING_STATES.map((state) => ({ state, items: items.filter((f) => f.state === state) }));
}

export function distinct(items: Finding[], key: (f: Finding) => string[]): string[] {
  return [...new Set(items.flatMap(key))].sort();
}

/** Parse "12, 15 20" into [12, 15, 20]; returns null if any token is not a non-negative integer. */
export function parseIdList(text: string): number[] | null {
  const tokens = text.split(/[\s,;]+/).filter(Boolean);
  if (tokens.some((t) => !/^\d+$/.test(t))) return null;
  return [...new Set(tokens.map(Number))];
}

export function parseTechniques(text: string): string[] {
  return [
    ...new Set(
      text
        .split(/[\s,;]+/)
        .map((t) => t.trim().toUpperCase())
        .filter((t) => /^T\d{4}(\.\d{3})?$/.test(t)),
    ),
  ];
}

export const MIN_RATIONALE = 10;
