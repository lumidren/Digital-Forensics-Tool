import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { Access } from "@/lib/roles";
import type { Finding } from "@/lib/types";
import { FindingDetail } from "./finding-detail";

const findingAction = vi.fn((_c: string, _f: string, body: { action: string }) =>
  Promise.resolve({ ...base, state: body.action === "confirm" ? "confirmed" : "approved" }),
);

vi.mock("@/lib/api-instance", () => ({
  api: {
    getEvent: (_c: string, id: number) => Promise.resolve({ id, timestamp: 0, message: `event ${id}` }),
    findingAction: (...args: [string, string, { action: string }]) => findingAction(...args),
  },
}));

const base: Finding = {
  id: "f1",
  case_id: "C-1",
  rule: "lateral_movement",
  title: "Lateral movement WS01 -> FS01",
  description: "Observed explicit credentials",
  severity: "high",
  confidence: 0.8,
  category: "lateral-movement",
  attack_techniques: ["T1078"],
  event_ids: [3, 4],
  evidence_sha256: [],
  details: {},
  first_ns: null,
  last_ns: null,
  state: "proposed",
  origin: "rule",
  confirmed_by: null,
  confirmed_at: null,
  approved_by: null,
  approved_at: null,
  examiner_rationale: null,
  reviewer_comment: null,
};

const access = (userId: string, role: Access["role"]): Access => ({
  userId,
  isAdmin: false,
  canUnmask: false,
  role,
});

function renderDetail(f: Finding, a: Access) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <FindingDetail caseId="C-1" finding={f} access={a} />
    </QueryClientProvider>,
  );
}

describe("FindingDetail role gating", () => {
  it("lets an examiner confirm only with a rationale", async () => {
    renderDetail(base, access("alice", "examiner"));
    const confirm = screen.getByRole("button", { name: "Confirm" });
    expect(confirm).toBeDisabled();
    expect(screen.getByTestId("gate-reason")).toHaveTextContent(/at least 10 characters/);
    await userEvent.type(screen.getByLabelText(/Rationale/), "Corroborated by 4624 type 3 logon");
    expect(confirm).toBeEnabled();
    await userEvent.click(confirm);
    expect(findingAction).toHaveBeenCalledWith("C-1", "f1", {
      action: "confirm",
      text: "Corroborated by 4624 type 3 logon",
    });
    expect(await screen.findByText("event 3")).toBeInTheDocument();
  });

  it("hides decisions from viewers", () => {
    renderDetail(base, access("vic", "viewer"));
    expect(screen.queryByRole("button", { name: "Confirm" })).toBeNull();
  });

  it("disables approval with an explanation for the confirming examiner", () => {
    const confirmed = {
      ...base,
      state: "confirmed" as const,
      confirmed_by: "alice",
      examiner_rationale: "Corroborated",
    };
    renderDetail(confirmed, access("alice", "lead"));
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(screen.getByTestId("gate-reason")).toHaveTextContent(/You confirmed this finding/);
    expect(screen.getByRole("button", { name: "Return to examiner" })).toBeEnabled();
  });

  it("allows an independent reviewer to approve", async () => {
    const confirmed = { ...base, state: "confirmed" as const, confirmed_by: "alice" };
    renderDetail(confirmed, access("bob", "reviewer"));
    const approve = screen.getByRole("button", { name: "Approve" });
    expect(approve).toBeEnabled();
    await userEvent.click(approve);
    expect(findingAction).toHaveBeenLastCalledWith("C-1", "f1", { action: "approve", text: "" });
  });

  it("blocks examiners from approving and offers reopen on rejected findings", () => {
    const confirmed = { ...base, state: "confirmed" as const, confirmed_by: "carol" };
    const { unmount } = renderDetail(confirmed, access("dave", "examiner"));
    expect(screen.getByRole("button", { name: "Approve" })).toBeDisabled();
    expect(screen.getByTestId("gate-reason")).toHaveTextContent(/reviewer role/);
    unmount();
    renderDetail({ ...base, state: "rejected" }, access("dave", "examiner"));
    expect(screen.getByRole("button", { name: "Reopen" })).toBeEnabled();
  });
});
