import { describe, expect, it } from "vitest";
import { accessFor, atLeast, canExamine, canReopen, canReturn, canReview, gate } from "./roles";
import type { Finding, Me } from "./types";

const me = (over: Partial<Me> = {}): Me => ({
  user_id: "alice",
  display_name: "Alice",
  is_admin: false,
  can_unmask_pii: false,
  cases: { "C-1": "examiner", "C-2": "lead" },
  signing_key_id: "k",
  ...over,
});

const finding = (over: Partial<Finding> = {}): Finding =>
  ({ id: "f", state: "proposed", confirmed_by: null, ...over }) as Finding;

describe("accessFor", () => {
  it("derives the role from /me or the case detail", () => {
    expect(accessFor(me(), "C-1").role).toBe("examiner");
    expect(accessFor(me(), "C-1", "reviewer").role).toBe("reviewer");
    expect(accessFor(me(), "C-9").role).toBeNull();
    expect(accessFor(me(), null).role).toBeNull();
    expect(accessFor(undefined, "C-1")).toEqual({ userId: "", isAdmin: false, canUnmask: false, role: null });
    expect(accessFor(me({ is_admin: true, cases: {} }), "C-9").role).toBe("lead");
    expect(accessFor(me({ can_unmask_pii: true }), "C-1").canUnmask).toBe(true);
  });
});

describe("role ranks", () => {
  it("orders viewer < examiner < reviewer < lead with admin override", () => {
    const ex = accessFor(me(), "C-1");
    expect(atLeast(ex, "viewer")).toBe(true);
    expect(atLeast(ex, "examiner")).toBe(true);
    expect(atLeast(ex, "reviewer")).toBe(false);
    expect(atLeast(accessFor(me(), "C-2"), "reviewer")).toBe(true);
    expect(atLeast(accessFor(me(), "C-9"), "viewer")).toBe(false);
    expect(atLeast({ userId: "a", isAdmin: true, canUnmask: true, role: null }, "lead")).toBe(true);
    expect(gate(ex, "lead")).toEqual({ allowed: false, reason: "Requires the lead role on this case." });
    expect(gate(ex, "examiner").allowed).toBe(true);
  });
});

describe("finding workflow gates", () => {
  const examiner = accessFor(me(), "C-1");
  const lead = accessFor(me(), "C-2");
  const bob = accessFor(me({ user_id: "bob", cases: { "C-2": "reviewer" } }), "C-2");
  const viewer = accessFor(me({ cases: { "C-1": "viewer" } }), "C-1");

  it("lets examiners decide proposed findings only", () => {
    expect(canExamine(examiner, finding()).allowed).toBe(true);
    expect(canExamine(viewer, finding()).reason).toMatch(/examiner/);
    expect(canExamine(examiner, finding({ state: "confirmed" })).allowed).toBe(false);
  });

  it("requires a different reviewer to approve", () => {
    const confirmedByAlice = finding({ state: "confirmed", confirmed_by: "alice" });
    expect(canReview(examiner, confirmedByAlice).reason).toMatch(/reviewer/);
    const self = canReview(lead, confirmedByAlice);
    expect(self.allowed).toBe(false);
    expect(self.reason).toMatch(/You confirmed this finding/);
    expect(canReview(bob, confirmedByAlice)).toEqual({ allowed: true, reason: null });
    expect(canReview(bob, finding()).allowed).toBe(false);
  });

  it("allows return of confirmed findings and reopening rejected ones", () => {
    const confirmed = finding({ state: "confirmed", confirmed_by: "alice" });
    expect(canReturn(lead, confirmed).allowed).toBe(true);
    expect(canReturn(examiner, confirmed).allowed).toBe(false);
    expect(canReturn(bob, finding()).allowed).toBe(false);
    expect(canReopen(examiner, finding({ state: "rejected" })).allowed).toBe(true);
    expect(canReopen(examiner, finding()).allowed).toBe(false);
    expect(canReopen(viewer, finding({ state: "rejected" })).allowed).toBe(false);
  });
});
