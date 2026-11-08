import { describe, expect, it } from "vitest";
import { confirmPhrase, isConfirmed, planTotals } from "./retention";
import type { DisposalCasePlan, DisposalObject } from "./types";

const obj = (address: string, size: number, lock: string | null = null): DisposalObject => ({
  address,
  sha256: address,
  md5: null,
  sha3_256: null,
  size,
  encrypted: true,
  present: true,
  object_lock_until: lock,
});

const casePlan = (over: Partial<DisposalCasePlan> = {}): DisposalCasePlan => ({
  case_id: "C-1",
  name: "Old",
  retention_until: null,
  ledger_id: "L-C-1",
  evidence_objects: [obj("a".repeat(64), 10), obj("b".repeat(64), 5, "2030-01-01T00:00:00Z")],
  derived_objects: [obj("c".repeat(64), 3)],
  kept_shared: [{ address: "d".repeat(64), evidence_id: "EV-1", referenced_by: ["C-2"] }],
  timeline_events: 7,
  report_files: [{ file: "r.pdf", size: 4, sha256: "e".repeat(64) }],
  intake_sessions: [{ session_id: "s1", files: 2, bytes: 9 }],
  pending_jobs: [],
  db_rows: { evidence: 2, notes: 1, memberships: 1 },
  memberships_kept: ["alice"],
  bytes: 31,
  ...over,
});

describe("retention helpers", () => {
  it("builds the API confirmation phrase", () => {
    expect(confirmPhrase("C-20260101-ABC123")).toBe("DISPOSE C-20260101-ABC123");
  });

  it("requires the exact case id", () => {
    expect(isConfirmed("C-1", "C-1")).toBe(true);
    expect(isConfirmed("  C-1 ", "C-1")).toBe(true);
    expect(isConfirmed("c-1", "C-1")).toBe(false);
    expect(isConfirmed("C-", "C-1")).toBe(false);
    expect(isConfirmed("DISPOSE C-1", "C-1")).toBe(false);
    expect(isConfirmed("", "")).toBe(false);
  });

  it("sums plan totals across cases", () => {
    expect(planTotals({ cases: [] })).toEqual({
      objects: 0,
      derived: 0,
      kept: 0,
      events: 0,
      rows: 0,
      files: 0,
      bytes: 0,
      objectLocked: 0,
    });
    const t = planTotals({ cases: [casePlan(), casePlan({ case_id: "C-2", timeline_events: 3, bytes: 1 })] });
    expect(t).toEqual({
      objects: 4,
      derived: 2,
      kept: 2,
      events: 10,
      rows: 8,
      files: 6,
      bytes: 32,
      objectLocked: 2,
    });
  });
});
