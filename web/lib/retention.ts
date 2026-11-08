/**
 * Retention disposal helpers: the confirmation phrase the API expects, the typed-id check the
 * console requires before enabling the destructive button, and plan totals for the summary.
 */
import type { DisposalCasePlan, DisposalPlan } from "./types";

/** Phrase the API requires per case on the real (non-dry) run. */
export function confirmPhrase(caseId: string): string {
  return `DISPOSE ${caseId}`;
}

/** True only when the operator typed the exact case id (surrounding whitespace ignored, case-sensitive). */
export function isConfirmed(typed: string, caseId: string): boolean {
  return caseId.length > 0 && typed.trim() === caseId;
}

export interface PlanTotals {
  objects: number;
  derived: number;
  kept: number;
  events: number;
  rows: number;
  files: number;
  bytes: number;
  objectLocked: number;
}

function caseTotals(c: DisposalCasePlan): PlanTotals {
  const objs = [...c.evidence_objects, ...c.derived_objects];
  return {
    objects: c.evidence_objects.length,
    derived: c.derived_objects.length,
    kept: c.kept_shared.length,
    events: c.timeline_events,
    rows: Object.values(c.db_rows).reduce((a, b) => a + b, 0),
    files: c.report_files.length + c.intake_sessions.reduce((a, s) => a + s.files, 0),
    bytes: c.bytes,
    objectLocked: objs.filter((o) => o.object_lock_until !== null).length,
  };
}

/** Sum of everything a plan would delete, across its cases. */
export function planTotals(plan: Pick<DisposalPlan, "cases">): PlanTotals {
  const zero: PlanTotals = {
    objects: 0,
    derived: 0,
    kept: 0,
    events: 0,
    rows: 0,
    files: 0,
    bytes: 0,
    objectLocked: 0,
  };
  return plan.cases.map(caseTotals).reduce(
    (acc, t) => ({
      objects: acc.objects + t.objects,
      derived: acc.derived + t.derived,
      kept: acc.kept + t.kept,
      events: acc.events + t.events,
      rows: acc.rows + t.rows,
      files: acc.files + t.files,
      bytes: acc.bytes + t.bytes,
      objectLocked: acc.objectLocked + t.objectLocked,
    }),
    zero,
  );
}
