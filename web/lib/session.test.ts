import { beforeEach, describe, expect, it, vi } from "vitest";
import { applyProgress, isActive, jobFraction, mergeJobs, parseProgress } from "./progress";
import { buildProcessTree, flattenTree, pidOf } from "./memory";
import {
  base64UrlEncode,
  beginLogin,
  completeLogin,
  discover,
  pkceChallenge,
  randomString,
  safeNext,
} from "./oidc";
import {
  clearToken,
  getToken,
  resetTokenMemory,
  setToken,
  subscribeToken,
  TOKEN_STORAGE_KEY,
} from "./token-store";
import type { Job, TimelineEvent } from "./types";

describe("token store", () => {
  beforeEach(() => {
    clearToken();
    resetTokenMemory();
  });

  it("keeps the token in memory and sessionStorage, never localStorage", () => {
    const fn = vi.fn();
    const off = subscribeToken(fn);
    setToken("secret-token", 60, 1000);
    expect(getToken(2000)).toBe("secret-token");
    expect(JSON.parse(sessionStorage.getItem(TOKEN_STORAGE_KEY) ?? "{}")).toEqual({
      token: "secret-token",
      expiresAt: 61_000,
    });
    expect(localStorage.length).toBe(0);
    expect(fn).toHaveBeenCalledTimes(1);
    off();
    clearToken();
    expect(fn).toHaveBeenCalledTimes(1);
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
    expect(getToken()).toBeNull();
  });

  it("restores from sessionStorage after a reload and expires", () => {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify({ token: "t", expiresAt: 5000 }));
    resetTokenMemory();
    expect(getToken(1000)).toBe("t");
    expect(getToken(6000)).toBeNull();
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("drops corrupt entries", () => {
    sessionStorage.setItem(TOKEN_STORAGE_KEY, "{not json");
    expect(getToken()).toBeNull();
    sessionStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify({ token: 5 }));
    resetTokenMemory();
    expect(getToken()).toBeNull();
    expect(sessionStorage.getItem(TOKEN_STORAGE_KEY)).toBeNull();
  });

  it("notifies only when something was cleared", () => {
    const fn = vi.fn();
    subscribeToken(fn);
    clearToken();
    expect(fn).not.toHaveBeenCalled();
  });
});

describe("progress", () => {
  const job = (over: Partial<Job> = {}): Job => ({
    job_id: "J-1",
    case_id: "C-1",
    evidence_sha256: "ff",
    kind: "auto",
    priority: 50,
    state: "running",
    created: "",
    updated: "",
    error: null,
    steps: [
      { name: "verify", state: "done", attempts: 1, progress: 1, message: "ok", duration_ms: 1 },
      { name: "parse", state: "pending", attempts: 0, progress: 0, message: null, duration_ms: null },
    ],
    ...over,
  });

  it("parses frames and folds them into per-step state", () => {
    expect(parseProgress(42)).toBeNull();
    expect(parseProgress("nope")).toBeNull();
    expect(parseProgress(JSON.stringify({ job_id: "J" }))).toBeNull();
    const m = parseProgress(
      JSON.stringify({ job_id: "J-1", step: "parse", state: "running", progress: 0.4, message: "50 files" }),
    );
    expect(m).not.toBeNull();
    let s = applyProgress({}, m ?? { job_id: "", step: "", state: "pending" });
    s = applyProgress(s, { job_id: "J-1", step: "parse", state: "running" });
    expect(s["J-1"]?.parse).toEqual({ state: "running", progress: 0.4, message: "50 files", error: null });
    s = applyProgress(s, { job_id: "J-1", step: "index", state: "done", cached: true });
    expect(s["J-1"]?.index).toEqual({
      state: "done",
      progress: 1,
      message: "reused cached output",
      error: null,
    });
    s = applyProgress(s, { job_id: "J-1", step: "parse", state: "failed", error: "boom" });
    expect(s["J-1"]?.parse?.error).toBe("boom");
    expect(applyProgress(s, { job_id: "", step: "x", state: "done" })).toBe(s);
  });

  it("merges live steps over polled jobs", () => {
    const merged = mergeJobs([job(), job({ job_id: "J-2" })], {
      "J-1": {
        parse: { state: "running", progress: 0.5, message: "half", error: null },
        extra: { state: "pending", progress: 0, message: null, error: null },
      },
    });
    expect(merged[0]?.steps.map((x) => [x.name, x.state, x.progress, x.message])).toEqual([
      ["verify", "done", 1, "ok"],
      ["parse", "running", 0.5, "half"],
      ["extra", "pending", 0, null],
    ]);
    expect(merged[1]).toEqual(job({ job_id: "J-2" }));
  });

  it("computes job fraction and activity", () => {
    expect(jobFraction(job())).toBe(0.5);
    expect(jobFraction(job({ state: "done" }))).toBe(1);
    expect(jobFraction(job({ steps: [] }))).toBe(0);
    expect(isActive(job())).toBe(true);
    expect(isActive(job({ state: "pending" }))).toBe(true);
    expect(isActive(job({ state: "failed" }))).toBe(false);
  });
});

describe("memory process tree", () => {
  let id = 0;
  const e = (
    data_type: string,
    attrs: Record<string, unknown>,
    timestamp: number | null = 100,
  ): TimelineEvent => ({ id: (id += 1), data_type, timestamp, attrs }) as unknown as TimelineEvent;

  it("builds parent/child links and flags anomalies", () => {
    const events = [
      e("memory:process", { plugin: "windows.pslist.PsList", PID: 4, PPID: 0, ImageFileName: "System" }),
      e("memory:process", { plugin: "windows.psscan.PsScan", PID: 4, PPID: 0, ImageFileName: "System" }, 50),
      e("memory:process", {
        plugin: "windows.pslist.PsList",
        PID: "500",
        PPID: "4",
        ImageFileName: "svchost.exe",
      }),
      e("memory:process", { plugin: "windows.pslist.PsList", PID: 600, PPID: 500, Name: "evil.exe" }),
      e("memory:process", {
        plugin: "windows.psscan.PsScan",
        PID: 666,
        PPID: 500,
        ImageFileName: "hidden.exe",
      }),
      e(
        "memory:process",
        { plugin: "windows.pslist.PsList", PID: 900, PPID: 12345, ImageFileName: "orphan.exe" },
        null,
      ),
      e("memory:injection", { plugin: "windows.malfind.Malfind", PID: 600 }),
      e("memory:injection", { plugin: "windows.hollowprocesses.HollowProcesses", PID: 600 }),
      e("memory:injection", { plugin: "windows.malfind.Malfind", PID: 999 }),
      e("memory:network:connection", { PID: 600 }),
      e("memory:process", { plugin: "x", ImageFileName: "no pid" }),
    ];
    const tree = buildProcessTree(events);
    expect(tree.roots.map((n) => n.pid)).toEqual([4, 900]);
    expect(tree.byPid.get(4)?.createNs).toBe(50);
    expect(tree.byPid.get(4)?.sources).toEqual(["pslist", "psscan"]);
    expect(tree.byPid.get(500)?.children.map((n) => n.pid)).toEqual([600, 666]);
    expect(tree.byPid.get(600)?.flags).toEqual(["malfind", "hollowing"]);
    expect(tree.byPid.get(600)?.name).toBe("evil.exe");
    expect(tree.byPid.get(600)?.connections).toBe(1);
    expect(tree.byPid.get(666)?.flags).toEqual(["hidden"]);
    expect(tree.byPid.get(900)?.flags).toEqual(["orphan"]);
    expect(tree.flagged.map((n) => n.pid)).toEqual([600, 666]);
    const flat = flattenTree(tree.roots, (pid) => pid !== 500);
    expect(flat.map((r) => [r.node.pid, r.depth])).toEqual([
      [4, 0],
      [500, 1],
      [900, 0],
    ]);
    expect(pidOf(e("x", { pid: 7 }))).toBe(7);
    expect(pidOf(e("x", { PID: "abc" }))).toBeNull();
  });
});

describe("OIDC PKCE", () => {
  const storage = sessionStorage;
  const discovery = {
    authorization_endpoint: "https://idp.test/auth",
    token_endpoint: "https://idp.test/token",
  };
  const cfg = { issuer: "https://idp.test", clientId: "veritas-web", scope: "openid profile" };

  function fetchMock(tokenBody: unknown, tokenStatus = 200) {
    return vi.fn((input: RequestInfo | URL) => {
      const url = input.toString();
      if (url.endsWith("/.well-known/openid-configuration"))
        return Promise.resolve(new Response(JSON.stringify(discovery)));
      return Promise.resolve(new Response(JSON.stringify(tokenBody), { status: tokenStatus }));
    }) as unknown as typeof fetch;
  }

  it("encodes base64url and derives the S256 challenge (RFC 7636 appendix B)", async () => {
    expect(base64UrlEncode(new Uint8Array([251, 255, 254]))).toBe("-__-");
    expect(await pkceChallenge(crypto, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")).toBe(
      "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
    );
    expect(randomString(crypto, 16)).toMatch(/^[A-Za-z0-9_-]{22}$/);
  });

  it("rejects incomplete discovery documents", async () => {
    await expect(
      discover("https://idp.test", (() => Promise.resolve(new Response("{}"))) as unknown as typeof fetch),
    ).rejects.toThrow(/incomplete/);
    await expect(
      discover("https://idp.test", (() =>
        Promise.resolve(new Response("", { status: 500 }))) as unknown as typeof fetch),
    ).rejects.toThrow(/500/);
  });

  it("runs the authorization-code flow end to end", async () => {
    const url = new URL(
      await beginLogin(cfg, "https://app/auth/callback", "/cases/C-1", {
        fetchImpl: fetchMock({}),
        crypto,
        storage,
      }),
    );
    expect(url.origin + url.pathname).toBe("https://idp.test/auth");
    expect(url.searchParams.get("code_challenge_method")).toBe("S256");
    expect(url.searchParams.get("client_id")).toBe("veritas-web");
    const state = url.searchParams.get("state") ?? "";
    const jwt = "aaa.bbb.ccc";
    const fetchImpl = fetchMock({ access_token: jwt, expires_in: 300 });
    const res = await completeLogin(
      cfg,
      new URLSearchParams({ code: "xyz", state }),
      "https://app/auth/callback",
      { fetchImpl, crypto, storage },
    );
    expect(res).toEqual({ token: jwt, expiresIn: 300, next: "/cases/C-1" });
    const tokenCall = (fetchImpl as unknown as { mock: { calls: [string, RequestInit][] } }).mock.calls[1];
    expect(String(tokenCall?.[1].body)).toContain("code_verifier=");
    expect(storage.getItem("veritas.oidc.pending")).toBeNull();
  });

  it("falls back to the ID token and validates the callback", async () => {
    const deps = (body: unknown, status = 200) => ({ fetchImpl: fetchMock(body, status), crypto, storage });
    const start = async () =>
      new URL(await beginLogin(cfg, "r", "//evil", deps({}))).searchParams.get("state") ?? "";
    let state = await start();
    expect(
      await completeLogin(
        cfg,
        new URLSearchParams({ code: "c", state }),
        "r",
        deps({ access_token: "opaque", id_token: "i.d.t" }),
      ),
    ).toEqual({
      token: "i.d.t",
      expiresIn: 3600,
      next: "/cases",
    });
    await expect(
      completeLogin(cfg, new URLSearchParams({ code: "c", state }), "r", deps({})),
    ).rejects.toThrow(/No sign-in/);
    state = await start();
    await expect(
      completeLogin(cfg, new URLSearchParams({ code: "c", state: "other" }), "r", deps({})),
    ).rejects.toThrow(/State mismatch/);
    await start();
    await expect(completeLogin(cfg, new URLSearchParams({ state }), "r", deps({}))).rejects.toThrow(
      /code missing/,
    );
    await expect(
      completeLogin(cfg, new URLSearchParams({ error: "access_denied" }), "r", deps({})),
    ).rejects.toThrow("access_denied");
    state = await start();
    await expect(
      completeLogin(cfg, new URLSearchParams({ code: "c", state }), "r", deps({}, 400)),
    ).rejects.toThrow(/Token exchange failed/);
    state = await start();
    await expect(
      completeLogin(cfg, new URLSearchParams({ code: "c", state }), "r", deps({ access_token: "opaque" })),
    ).rejects.toThrow(/no usable token/);
  });

  it("only allows same-origin relative destinations", () => {
    expect(safeNext("/cases/C-1")).toBe("/cases/C-1");
    expect(safeNext("//evil.test")).toBe("/cases");
    expect(safeNext("https://evil.test")).toBe("/cases");
    expect(safeNext("/\\evil")).toBe("/cases");
    expect(safeNext(null)).toBe("/cases");
  });
});
