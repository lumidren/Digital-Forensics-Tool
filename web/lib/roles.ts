/** Role-based UI gating. The API is the authority; these checks only decide what to show. */
import type { CaseRole, Finding, Me } from "./types";

export const ROLE_RANK: Record<CaseRole, number> = { viewer: 0, examiner: 1, reviewer: 2, lead: 3 };

export interface Access {
  userId: string;
  isAdmin: boolean;
  canUnmask: boolean;
  role: CaseRole | null;
}

export function accessFor(me: Me | undefined, caseId: string | null, caseRole?: CaseRole | null): Access {
  const role = caseRole ?? (caseId ? (me?.cases[caseId] ?? null) : null);
  return {
    userId: me?.user_id ?? "",
    isAdmin: me?.is_admin ?? false,
    canUnmask: me?.can_unmask_pii ?? false,
    role: role ?? (me?.is_admin ? "lead" : null),
  };
}

export function atLeast(a: Access, min: CaseRole): boolean {
  if (a.isAdmin) return true;
  return a.role !== null && ROLE_RANK[a.role] >= ROLE_RANK[min];
}

export interface Gate {
  allowed: boolean;
  reason: string | null;
}

const ok: Gate = { allowed: true, reason: null };
const need = (role: CaseRole): Gate => ({
  allowed: false,
  reason: `Requires the ${role} role on this case.`,
});

export function gate(a: Access, min: CaseRole): Gate {
  return atLeast(a, min) ? ok : need(min);
}

/** Examiner decisions on a proposed finding. */
export function canExamine(a: Access, f: Finding): Gate {
  if (!atLeast(a, "examiner")) return need("examiner");
  if (f.state !== "proposed")
    return {
      allowed: false,
      reason: `Finding is ${f.state}; only proposed findings can be confirmed or rejected.`,
    };
  return ok;
}

/** Reviewer decisions on a confirmed finding; the confirming examiner may not approve it. */
export function canReview(a: Access, f: Finding): Gate {
  if (!atLeast(a, "reviewer")) return need("reviewer");
  if (f.state !== "confirmed")
    return {
      allowed: false,
      reason: `Finding is ${f.state}; only confirmed findings can be approved or returned.`,
    };
  if (f.confirmed_by === a.userId) {
    return {
      allowed: false,
      reason: "You confirmed this finding. A different reviewer must approve it (separation of duties).",
    };
  }
  return ok;
}

export function canReturn(a: Access, f: Finding): Gate {
  if (!atLeast(a, "reviewer")) return need("reviewer");
  if (f.state !== "confirmed")
    return { allowed: false, reason: `Finding is ${f.state}; only confirmed findings can be returned.` };
  return ok;
}

export function canReopen(a: Access, f: Finding): Gate {
  if (!atLeast(a, "examiner")) return need("examiner");
  if (f.state !== "rejected") return { allowed: false, reason: "Only rejected findings can be reopened." };
  return ok;
}
