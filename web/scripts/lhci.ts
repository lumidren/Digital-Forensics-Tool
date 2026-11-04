/**
 * Lighthouse CI against the production build: boots the native stack (API, seed, `next start`),
 * then runs `lhci autorun` on the login page and the seeded case dashboard.
 *
 *   npm run lhci                       (set LHCI_CHROME_PATH to use a specific Chrome)
 */
import { spawnSync } from "node:child_process";
import { existsSync, readdirSync, rmSync } from "node:fs";
import { dirname, join } from "node:path";
import { chromium } from "@playwright/test";
import { startStack, stopStack, WEB_DIR } from "../e2e/stack.ts";

/** Prefer Playwright's headless shell: it launches where full Chrome builds may be blocked by policy. */
function chromePath(): string {
  if (process.env.LHCI_CHROME_PATH) return process.env.LHCI_CHROME_PATH;
  const full = chromium.executablePath();
  const root = dirname(dirname(dirname(full)));
  const exe = process.platform === "win32" ? "chrome-headless-shell.exe" : "chrome-headless-shell";
  for (const dir of existsSync(root)
    ? readdirSync(root)
        .filter((d) => d.startsWith("chromium_headless_shell-"))
        .sort()
        .reverse()
    : []) {
    for (const sub of readdirSync(join(root, dir))) {
      const candidate = join(root, dir, sub, exe);
      if (existsSync(candidate)) return candidate;
    }
  }
  return full;
}

rmSync(join(WEB_DIR, ".lighthouseci"), { recursive: true, force: true });
const state = await startStack({ distDir: ".next-e2e", reuseBuild: process.env.E2E_REUSE_BUILD === "1" });
let status = 1;
try {
  const lhci = spawnSync(
    process.execPath,
    [
      "node_modules/@lhci/cli/src/cli.js",
      "autorun",
      "--config=lighthouserc.json",
      `--collect.url=${state.webUrl}/login`,
      `--collect.url=${state.webUrl}/cases/${encodeURIComponent(state.caseId)}`,
      `--collect.chromePath=${chromePath()}`,
    ],
    { cwd: WEB_DIR, stdio: "inherit" },
  );
  status = lhci.status ?? 1;
} finally {
  stopStack(state);
}
process.exit(status);
