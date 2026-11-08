import { describe, expect, it, vi } from "vitest";
import { ApiError, buildQuery, createApiClient, filenameFromDisposition, type MinimalXhr } from "./api";

function jsonResponse(body: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

function setup(
  token: string | null = "tok-123",
  responder: (url: string, init: RequestInit) => Response = () => jsonResponse({}),
) {
  const calls: { url: string; init: RequestInit }[] = [];
  const onUnauthorized = vi.fn();
  const fetchImpl = vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input.toString();
    calls.push({ url, init: init ?? {} });
    return Promise.resolve(responder(url, init ?? {}));
  });
  const client = createApiClient({
    baseUrl: "http://api.test",
    getToken: () => token,
    onUnauthorized,
    fetchImpl,
  });
  return { client, calls, onUnauthorized };
}

describe("buildQuery", () => {
  it("skips empty values and encodes the rest", () => {
    expect(buildQuery(undefined)).toBe("");
    expect(buildQuery({ a: undefined, b: null, c: "" })).toBe("");
    expect(buildQuery({ q: "a b", n: 2, t: true })).toBe("?q=a+b&n=2&t=true");
  });
});

describe("filenameFromDisposition", () => {
  it("extracts quoted, unquoted and RFC 5987 names", () => {
    expect(filenameFromDisposition('attachment; filename="C-1-timeline.csv"', "x")).toBe("C-1-timeline.csv");
    expect(filenameFromDisposition("attachment; filename=report.pdf", "x")).toBe("report.pdf");
    expect(filenameFromDisposition("attachment; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf", "x")).toBe(
      "résumé.pdf",
    );
    expect(filenameFromDisposition(null, "fallback.bin")).toBe("fallback.bin");
    expect(filenameFromDisposition("inline", "fallback.bin")).toBe("fallback.bin");
  });
});

describe("createApiClient", () => {
  it("sends the bearer token and JSON body", async () => {
    const { client, calls } = setup("abc", () => jsonResponse({ id: "C-1" }, 201));
    const res = await client.createCase({ name: "Case" });
    expect(res).toEqual({ id: "C-1" });
    const call = calls[0];
    expect(call?.url).toBe("http://api.test/api/v1/cases");
    expect(call?.init.method).toBe("POST");
    const h = new Headers(call?.init.headers);
    expect(h.get("Authorization")).toBe("Bearer abc");
    expect(h.get("Content-Type")).toBe("application/json");
    expect(call?.init.body).toBe(JSON.stringify({ name: "Case" }));
  });

  it("omits Authorization without a token", async () => {
    const { client, calls } = setup(null, () =>
      jsonResponse({ access_token: "t", token_type: "bearer", expires_in: 10 }),
    );
    await client.login("alice", "pw");
    expect(new Headers(calls[0]?.init.headers).has("Authorization")).toBe(false);
  });

  it("raises ApiError with the API detail and reports 401", async () => {
    const { client, onUnauthorized } = setup("t", () =>
      jsonResponse({ detail: "invalid or expired token" }, 401),
    );
    await expect(client.me()).rejects.toMatchObject({ status: 401, detail: "invalid or expired token" });
    expect(onUnauthorized).toHaveBeenCalledOnce();
  });

  it("formats validation errors and falls back to status text", async () => {
    const v = setup("t", () =>
      jsonResponse({ detail: [{ loc: ["body", "name"], msg: "field required" }] }, 422),
    );
    await expect(v.client.createCase({ name: "" })).rejects.toThrow("name: field required");
    const t = setup("t", () => new Response("boom", { status: 500, statusText: "Server Error" }));
    await expect(t.client.listCases()).rejects.toMatchObject({ detail: "Server Error" });
    const o = setup("t", () => jsonResponse({ other: 1 }, 409));
    const err = await o.client.listCases().catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).detail).toBe("request failed");
  });

  it("formats structured refusals", async () => {
    const r = setup("t", () =>
      jsonResponse(
        {
          detail: {
            message: "disposal refused",
            refused: [{ case_id: "C-1", reason: "case is on legal hold" }],
          },
        },
        409,
      ),
    );
    await expect(r.client.planDisposal(["C-1"], "elapsed")).rejects.toMatchObject({
      status: 409,
      detail: "disposal refused (C-1: case is on legal hold)",
    });
    const m = setup("t", () => jsonResponse({ detail: { message: "confirmation phrase missing" } }, 422));
    await expect(m.client.dispose(["C-1"], "elapsed", "t", [])).rejects.toMatchObject({
      detail: "confirmation phrase missing",
    });
  });

  it("returns undefined for 204", async () => {
    const { client } = setup("t", () => new Response(null, { status: 204 }));
    await expect(client.request("/x")).resolves.toBeUndefined();
  });

  it("downloads blobs with the server filename", async () => {
    const { client, calls } = setup(
      "t",
      () =>
        new Response("a,b\n", {
          status: 200,
          headers: {
            "Content-Disposition": 'attachment; filename="C-1-timeline.csv"',
            "X-Content-SHA256": "ff",
          },
        }),
    );
    const d = await client.exportTimeline("C-1", "csv", true);
    expect(d.filename).toBe("C-1-timeline.csv");
    expect(await d.blob.text()).toBe("a,b\n");
    expect(d.headers.get("X-Content-SHA256")).toBe("ff");
    expect(calls[0]?.url).toBe("http://api.test/api/v1/cases/C-1/timeline/export?fmt=csv&unmask=true");
  });

  it("builds the WebSocket URL with the token", () => {
    const { client } = setup("t/k");
    expect(client.wsUrl("C 1")).toBe("ws://api.test/api/v1/cases/C%201/ws?access_token=t%2Fk");
  });

  it("maps every route to the expected method and path", async () => {
    const { client, calls } = setup("t", () => jsonResponse({ ok: true }));
    const c = "C-1";
    const routes: [() => Promise<unknown>, string, string][] = [
      [() => client.me(), "GET", "/api/v1/me"],
      [() => client.listCases(), "GET", "/api/v1/cases"],
      [() => client.getCase(c), "GET", "/api/v1/cases/C-1"],
      [() => client.patchCase(c, { status: "review" }), "PATCH", "/api/v1/cases/C-1"],
      [() => client.setMember(c, { user_id: "bob", role: "reviewer" }), "POST", "/api/v1/cases/C-1/members"],
      [() => client.removeMember(c, "bob"), "DELETE", "/api/v1/cases/C-1/members/bob"],
      [() => client.activity(c), "GET", "/api/v1/cases/C-1/activity?limit=50"],
      [() => client.listEvidence(c), "GET", "/api/v1/cases/C-1/evidence"],
      [() => client.getEvidence(c, "EV-1"), "GET", "/api/v1/cases/C-1/evidence/EV-1"],
      [
        () => client.evidenceBytes(c, "EV-1", 16, 32),
        "GET",
        "/api/v1/cases/C-1/evidence/EV-1/bytes?offset=16&length=32",
      ],
      [() => client.verifyEvidence(c, "EV-1"), "POST", "/api/v1/cases/C-1/evidence/EV-1/verify"],
      [() => client.reprocessEvidence(c, "EV-1"), "POST", "/api/v1/cases/C-1/evidence/EV-1/reprocess"],
      [() => client.listJobs(c), "GET", "/api/v1/cases/C-1/jobs"],
      [() => client.search(c, { text: "x" }), "POST", "/api/v1/cases/C-1/timeline/search"],
      [() => client.histogram(c, {}), "POST", "/api/v1/cases/C-1/timeline/histogram?bucket=auto"],
      [() => client.facets(c, "host", {}), "POST", "/api/v1/cases/C-1/timeline/facets/host"],
      [() => client.getEvent(c, 7), "GET", "/api/v1/cases/C-1/events/7"],
      [() => client.getEvent(c, 7, true), "GET", "/api/v1/cases/C-1/events/7?unmask=true"],
      [() => client.listViews(c), "GET", "/api/v1/cases/C-1/views"],
      [() => client.createView(c, { name: "v", query: {} }), "POST", "/api/v1/cases/C-1/views"],
      [() => client.listBookmarks(c), "GET", "/api/v1/cases/C-1/bookmarks"],
      [() => client.createBookmark(c, { event_id: 1 }), "POST", "/api/v1/cases/C-1/bookmarks"],
      [() => client.deleteBookmark(c, 3), "DELETE", "/api/v1/cases/C-1/bookmarks/3"],
      [
        () => client.listNotes(c, "event", "1"),
        "GET",
        "/api/v1/cases/C-1/notes?target_type=event&target_id=1",
      ],
      [
        () => client.createNote(c, { target_type: "event", target_id: "1", body: "b" }),
        "POST",
        "/api/v1/cases/C-1/notes",
      ],
      [() => client.listHypotheses(c), "GET", "/api/v1/cases/C-1/hypotheses"],
      [
        () => client.createHypothesis(c, { title: "t", statement: "s" }),
        "POST",
        "/api/v1/cases/C-1/hypotheses",
      ],
      [
        () => client.updateHypothesis(c, 2, { title: "t", statement: "s" }),
        "PUT",
        "/api/v1/cases/C-1/hypotheses/2",
      ],
      [() => client.listTasks(c), "GET", "/api/v1/cases/C-1/tasks"],
      [() => client.createTask(c, { title: "t" }), "POST", "/api/v1/cases/C-1/tasks"],
      [() => client.updateTask(c, 4, { title: "t" }), "PUT", "/api/v1/cases/C-1/tasks/4"],
      [() => client.runFindings(c), "POST", "/api/v1/cases/C-1/findings/run"],
      [() => client.listFindings(c, "approved"), "GET", "/api/v1/cases/C-1/findings?state=approved"],
      [
        () => client.createFinding(c, { title: "t", description: "d", severity: "low" }),
        "POST",
        "/api/v1/cases/C-1/findings",
      ],
      [
        () => client.findingAction(c, "f1", { action: "confirm", text: "because ..." }),
        "POST",
        "/api/v1/cases/C-1/findings/f1/action",
      ],
      [() => client.lateral(c), "GET", "/api/v1/cases/C-1/analytics/lateral"],
      [() => client.provenance(c), "GET", "/api/v1/cases/C-1/analytics/provenance"],
      [() => client.attackTechniques(), "GET", "/api/v1/meta/attack"],
      [() => client.listIocs(c), "GET", "/api/v1/cases/C-1/iocs"],
      [() => client.importIocs(c, "1.2.3.4"), "POST", "/api/v1/cases/C-1/iocs"],
      [() => client.deleteIoc(c, 9), "DELETE", "/api/v1/cases/C-1/iocs/9"],
      [() => client.sweepIocs(c), "POST", "/api/v1/cases/C-1/iocs/sweep"],
      [() => client.stix(c), "GET", "/api/v1/cases/C-1/iocs/stix"],
      [
        () => client.custody(c, { kind: "ingest", offset: 0, limit: 10 }),
        "GET",
        "/api/v1/cases/C-1/custody?kind=ingest&offset=0&limit=10",
      ],
      [() => client.verifyCustody(c), "GET", "/api/v1/cases/C-1/custody/verify"],
      [() => client.exportCustody(c), "GET", "/api/v1/cases/C-1/custody/export"],
      [() => client.anchorCustody(c), "POST", "/api/v1/cases/C-1/custody/anchor"],
      [() => client.createReport(c, { format: "pdf" }), "POST", "/api/v1/cases/C-1/reports"],
      [() => client.listReports(c), "GET", "/api/v1/cases/C-1/reports"],
      [
        () => client.reportSignature(c, "R-1"),
        "GET",
        "/api/v1/cases/C-1/reports/R-1/download?part=signature",
      ],
      [
        () => client.downloadReport(c, "R-1", "document"),
        "GET",
        "/api/v1/cases/C-1/reports/R-1/download?part=document",
      ],
      [() => client.listUsers(), "GET", "/api/v1/admin/users"],
      [() => client.createUser({ id: "zed", display_name: "Zed" }), "POST", "/api/v1/admin/users"],
      [() => client.patchUser("zed", { active: false }), "PATCH", "/api/v1/admin/users/zed"],
      [() => client.keys(), "GET", "/api/v1/admin/keys"],
      [() => client.revokeKey("zed"), "POST", "/api/v1/admin/keys/zed/revoke"],
      [() => client.audit({ actor: "alice", limit: 5 }), "GET", "/api/v1/admin/audit?actor=alice&limit=5"],
      [() => client.verifyAudit(), "GET", "/api/v1/admin/audit/verify"],
      [() => client.retentionSweep(), "POST", "/api/v1/admin/retention/sweep"],
      [() => client.planDisposal(["C-1"], "elapsed"), "POST", "/api/v1/admin/retention/dispose?dry_run=true"],
      [
        () => client.dispose(["C-1"], "elapsed", "tok", ["DISPOSE C-1"]),
        "POST",
        "/api/v1/admin/retention/dispose?dry_run=false",
      ],
      [() => client.verifyStore(), "GET", "/api/v1/admin/store/verify"],
    ];
    for (const [fn] of routes) await fn();
    expect(calls.map((x) => [x.init.method, x.url.replace("http://api.test", "")])).toEqual(
      routes.map(([, m, p]) => [m, p]),
    );
  });
});

class FakeXhr implements MinimalXhr {
  static last: FakeXhr | null = null;
  status = 0;
  responseText = "";
  upload: MinimalXhr["upload"] = { onprogress: null };
  onload: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onabort: (() => void) | null = null;
  method = "";
  url = "";
  headers: Record<string, string> = {};
  body: FormData | null = null;
  constructor() {
    FakeXhr.last = this;
  }
  open(method: string, url: string) {
    this.method = method;
    this.url = url;
  }
  setRequestHeader(k: string, v: string) {
    this.headers[k] = v;
  }
  send(body: FormData) {
    this.body = body;
  }
  abort() {
    this.onabort?.();
  }
}

describe("uploadEvidence", () => {
  const file = new File(["hello"], "notes.txt", { type: "text/plain" });

  function client(token: string | null = "tok") {
    const onUnauthorized = vi.fn();
    const c = createApiClient({
      baseUrl: "http://api.test",
      getToken: () => token,
      onUnauthorized,
      xhrFactory: () => new FakeXhr(),
    });
    return { c, onUnauthorized };
  }

  it("posts multipart form data and reports progress", async () => {
    const { c } = client();
    const progress = vi.fn();
    const h = c.uploadEvidence(
      "C-1",
      file,
      { kind: "file", host: "WS01", tz_name: "UTC", clock_skew_ms: 5, expected_sha256: "ab" },
      progress,
    );
    const x = FakeXhr.last;
    expect(x?.url).toBe("http://api.test/api/v1/cases/C-1/evidence");
    expect(x?.headers.Authorization).toBe("Bearer tok");
    expect(x?.body?.get("kind")).toBe("file");
    expect(x?.body?.get("host")).toBe("WS01");
    expect(x?.body?.get("clock_skew_ms")).toBe("5");
    expect(x?.body?.get("description")).toBeNull();
    x?.upload.onprogress?.({ loaded: 2, total: 5, lengthComputable: true });
    x?.upload.onprogress?.({ loaded: 3, total: 0, lengthComputable: false });
    expect(progress).toHaveBeenNthCalledWith(1, 2, 5);
    expect(progress).toHaveBeenNthCalledWith(2, 3, file.size);
    if (x) {
      x.status = 201;
      x.responseText = JSON.stringify({ id: "EV-1", job_id: "J-1" });
      x.onload?.();
    }
    await expect(h.promise).resolves.toMatchObject({ id: "EV-1" });
  });

  it("rejects with the API detail, flags 401, and handles network errors and abort", async () => {
    const { c, onUnauthorized } = client(null);
    const h1 = c.uploadEvidence("C-1", file, { kind: "file" }, () => undefined);
    const x1 = FakeXhr.last;
    expect(x1?.headers.Authorization).toBeUndefined();
    if (x1) {
      x1.status = 409;
      x1.responseText = JSON.stringify({ detail: "hash mismatch" });
      x1.onload?.();
    }
    await expect(h1.promise).rejects.toMatchObject({ status: 409, detail: "hash mismatch" });

    const h2 = c.uploadEvidence("C-1", file, { kind: "file" }, () => undefined);
    const x2 = FakeXhr.last;
    if (x2) {
      x2.status = 401;
      x2.responseText = "not json";
      x2.onload?.();
    }
    await expect(h2.promise).rejects.toMatchObject({ status: 401, detail: "upload failed" });
    expect(onUnauthorized).toHaveBeenCalledOnce();

    const h3 = c.uploadEvidence("C-1", file, { kind: "file" }, () => undefined);
    FakeXhr.last?.onerror?.();
    await expect(h3.promise).rejects.toMatchObject({ status: 0, detail: "network error during upload" });

    const h4 = c.uploadEvidence("C-1", file, { kind: "file" }, () => undefined);
    h4.abort();
    await expect(h4.promise).rejects.toMatchObject({ detail: "upload cancelled" });
  });
});
