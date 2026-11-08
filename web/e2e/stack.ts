/**
 * Boots the full Veritas stack natively for end-to-end tests and Lighthouse runs:
 * API (uvicorn) on a free port with a temporary data directory, users, a seeded case, and the
 * Next.js production build served by `next start`. No containers are involved.
 */
import { spawn, spawnSync, type ChildProcess } from "node:child_process";
import { randomBytes } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

/** The web package directory (commands run from `web/` or from the repository root). */
export const WEB_DIR = existsSync(join(process.cwd(), "e2e", "stack.ts"))
  ? process.cwd()
  : resolve(process.cwd(), "web");
export const REPO_DIR = resolve(WEB_DIR, "..");
export const STATE_FILE = join(WEB_DIR, "e2e", ".state", "stack.json");
const IS_WIN = process.platform === "win32";

export interface UserCreds {
  username: string;
  password: string;
}

export interface StackState {
  apiUrl: string;
  webUrl: string;
  dataDir: string;
  pids: number[];
  caseId: string;
  caseName: string;
  evidenceId: string;
  users: { admin: UserCreds; alice: UserCreds; bob: UserCreds };
}

function python(): string {
  const candidates = IS_WIN
    ? [join(REPO_DIR, ".venv", "Scripts", "python.exe")]
    : [join(REPO_DIR, ".venv", "bin", "python"), join(REPO_DIR, ".venv", "bin", "python3")];
  const found = candidates.find((p) => existsSync(p));
  if (!found) throw new Error(`Python virtualenv not found under ${REPO_DIR}/.venv`);
  return found;
}

export function freePort(preferred = 0): Promise<number> {
  return new Promise((resolvePort, reject) => {
    const srv = createServer();
    srv.once("error", (err: NodeJS.ErrnoException) => {
      if (preferred !== 0 && err.code === "EADDRINUSE") {
        freePort(0).then(resolvePort, reject);
      } else {
        reject(err);
      }
    });
    srv.listen(preferred, "127.0.0.1", () => {
      const addr = srv.address();
      const port = typeof addr === "object" && addr ? addr.port : 0;
      srv.close(() => resolvePort(port));
    });
  });
}

function password(): string {
  return `${randomBytes(12).toString("base64url")}-Aa1`;
}

function run(cmd: string, args: string[], env: NodeJS.ProcessEnv, cwd = REPO_DIR): string {
  const r = spawnSync(cmd, args, { cwd, env, encoding: "utf8", shell: false, maxBuffer: 64 * 1024 * 1024 });  // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process - test harness spawning fixed local commands
  if (r.status !== 0) {
    throw new Error(`${cmd} ${args.join(" ")} failed (${r.status}):\n${r.stdout}\n${r.stderr}`);
  }
  return r.stdout;
}

function start(
  cmd: string,
  args: string[],
  env: NodeJS.ProcessEnv,
  cwd: string,
  logFile: string,
): ChildProcess {
  const child = spawn(cmd, args, {  // nosemgrep: javascript.lang.security.detect-child-process.detect-child-process - test harness spawning fixed local commands
    cwd,
    env,
    stdio: ["ignore", "pipe", "pipe"],
    shell: false,
    windowsHide: true,
  });
  const chunks: string[] = [];
  const keep = (b: Buffer) => {
    chunks.push(b.toString("utf8"));
    writeFileSync(logFile, chunks.join(""));
  };
  child.stdout?.on("data", keep);
  child.stderr?.on("data", keep);
  return child;
}

async function waitFor(url: string, timeoutMs: number, what: string): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let last = "";
  while (Date.now() < deadline) {
    try {
      const r = await fetch(url);
      if (r.ok) return;
      last = `HTTP ${r.status}`;
    } catch (err) {
      last = String(err);
    }
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error(`${what} did not become ready at ${url}: ${last}`);
}

async function api<T>(base: string, path: string, token: string | null, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && typeof init.body === "string") headers.set("Content-Type", "application/json");
  const r = await fetch(`${base}${path}`, { ...init, headers });
  if (!r.ok) throw new Error(`${init.method ?? "GET"} ${path} -> ${r.status} ${await r.text()}`);
  return (await r.json()) as T;
}

export async function login(base: string, u: UserCreds): Promise<string> {
  const res = await api<{ access_token: string }>(base, "/api/v1/auth/login", null, {
    method: "POST",
    body: JSON.stringify({ username: u.username, password: u.password }),
  });
  return res.access_token;
}

export function killTree(pid: number): void {
  try {
    if (IS_WIN) spawnSync("taskkill", ["/PID", String(pid), "/T", "/F"], { stdio: "ignore" });
    else process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid);
    } catch {
      /* already gone */
    }
  }
}

export interface StartOptions {
  /** Output directory for the Next.js build (kept apart from the regular `.next`). */
  distDir?: string;
  /** Reuse an existing build in distDir built for the same API URL. */
  reuseBuild?: boolean;
  log?: (msg: string) => void;
}

export async function startStack(opts: StartOptions = {}): Promise<StackState> {
  const log = opts.log ?? ((m: string) => console.log(`[stack] ${m}`));
  const distDir = opts.distDir ?? ".next-e2e";
  const py = python();
  const dataDir = mkdtempSync(join(tmpdir(), "veritas-e2e-"));
  const logs = join(dataDir, "logs");
  mkdirSync(logs);
  const apiPort = await freePort(18765);
  const webPort = await freePort(13100);
  const apiUrl = `http://127.0.0.1:${apiPort}`;
  const webUrl = `http://127.0.0.1:${webPort}`;
  const users = {
    admin: { username: "admin", password: password() },
    alice: { username: "alice", password: password() },
    bob: { username: "bob", password: password() },
  };
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    VERITAS_DATA_DIR: dataDir,
    VERITAS_MASTER_KEY: randomBytes(32).toString("hex"),
    VERITAS_CORS_ORIGINS: `${webUrl},http://localhost:${webPort}`,
    PYTHONPATH: join(REPO_DIR, "python"),
    PYTHONIOENCODING: "utf-8",
  };
  const pids: number[] = [];

  log(`data dir ${dataDir}`);
  run(py, ["-m", "veritas.api.manage", "create-admin", "--id", "admin", "--name", "Admin"], {
    ...env,
    VERITAS_ADMIN_PASSWORD: users.admin.password,
  });
  run(py, ["-m", "veritas.api.manage", "create-user", "--id", "alice", "--name", "Alice Examiner"], {
    ...env,
    VERITAS_USER_PASSWORD: users.alice.password,
  });
  run(py, ["-m", "veritas.api.manage", "create-user", "--id", "bob", "--name", "Bob Reviewer"], {
    ...env,
    VERITAS_USER_PASSWORD: users.bob.password,
  });

  const apiProc = start(
    py,
    [
      "-m",
      "uvicorn",
      "veritas.api.main:create_app",
      "--factory",
      "--host",
      "127.0.0.1",
      "--port",
      String(apiPort),
    ],
    env,
    REPO_DIR,
    join(logs, "api.log"),
  );
  if (apiProc.pid) pids.push(apiProc.pid);
  await waitFor(`${apiUrl}/healthz`, 60_000, "API");
  log(`API ready at ${apiUrl}`);

  // Seed: alice creates the case (lead), adds bob as reviewer, uploads evidence; events are inserted directly.
  const alice = await login(apiUrl, users.alice);
  const caseName = "Operation Lantern";
  const kase = await api<{ id: string }>(apiUrl, "/api/v1/cases", alice, {
    method: "POST",
    body: JSON.stringify({ name: caseName, description: "Seeded case for end-to-end tests" }),
  });
  await api(apiUrl, `/api/v1/cases/${kase.id}/members`, alice, {
    method: "POST",
    body: JSON.stringify({ user_id: "bob", role: "reviewer" }),
  });
  const form = new FormData();
  const payload = Buffer.concat([
    Buffer.from("MZ\x90\x00", "latin1"),
    Buffer.from("Veritas seeded evidence object. ".repeat(160)),
  ]);
  form.append("file", new Blob([payload]), "triage-WS01.bin");
  form.append("kind", "file");
  form.append("host", "WS01");
  const ev = await api<{ id: string; sha256: string }>(apiUrl, `/api/v1/cases/${kase.id}/evidence`, alice, {
    method: "POST",
    body: form,
  });
  const seeded = run(
    py,
    [join(WEB_DIR, "e2e", "seed.py"), "--case", kase.id, "--evidence-sha256", ev.sha256],
    env,
  );
  log(`seeded ${seeded.trim()}`);
  await api(apiUrl, `/api/v1/cases/${kase.id}/findings/run`, alice, { method: "POST" });

  const nextBin = join(WEB_DIR, "node_modules", "next", "dist", "bin", "next");
  const webEnv: NodeJS.ProcessEnv = {
    ...process.env,
    NEXT_DIST_DIR: distDir,
    NEXT_PUBLIC_API_URL: apiUrl,
    NEXT_TELEMETRY_DISABLED: "1",
  };
  const marker = join(WEB_DIR, distDir, "veritas-api-url");
  const reusable = opts.reuseBuild && existsSync(marker) && readFileSync(marker, "utf8") === apiUrl;
  if (!reusable) {
    log(`building web app for ${apiUrl} into ${distDir}`);
    run(process.execPath, [nextBin, "build"], webEnv, WEB_DIR);
    writeFileSync(marker, apiUrl);
  }
  const webProc = start(
    process.execPath,
    [nextBin, "start", "-p", String(webPort), "-H", "127.0.0.1"],
    webEnv,
    WEB_DIR,
    join(logs, "web.log"),
  );
  if (webProc.pid) pids.push(webProc.pid);
  await waitFor(`${webUrl}/login`, 60_000, "web");
  log(`web ready at ${webUrl}`);

  const state: StackState = {
    apiUrl,
    webUrl,
    dataDir,
    pids,
    caseId: kase.id,
    caseName,
    evidenceId: ev.id,
    users,
  };
  mkdirSync(dirname(STATE_FILE), { recursive: true });
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
  return state;
}

export function readState(): StackState {
  return JSON.parse(readFileSync(STATE_FILE, "utf8")) as StackState;
}

export function stopStack(state: StackState | null = existsSync(STATE_FILE) ? readState() : null): void {
  if (!state) return;
  for (const pid of [...state.pids].reverse()) killTree(pid);
  try {
    rmSync(state.dataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 300 });
  } catch {
    /* Windows may hold a handle briefly; the OS temp dir is cleaned eventually */
  }
  rmSync(STATE_FILE, { force: true });
}
