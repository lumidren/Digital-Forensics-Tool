/**
 * README screenshots: boots the native stack (API, seeded case, `next start`), signs in as the
 * examiner and captures each main screen in light and dark themes into docs/images/ui/.
 *
 *   npm run screenshots
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium, type Page } from "@playwright/test";
import { REPO_DIR, startStack, stopStack } from "../e2e/stack.ts";

const OUT = join(REPO_DIR, "docs", "images", "ui");

interface Shot {
  name: string;
  path: (caseId: string) => string;
  /** Optional interaction before the capture (open a drawer, select a row, ...). */
  prepare?: (page: Page) => Promise<void>;
}

const enc = encodeURIComponent;
const SHOTS: Shot[] = [
  { name: "cases", path: () => "/cases" },
  { name: "dashboard", path: (c) => `/cases/${enc(c)}` },
  { name: "evidence", path: (c) => `/cases/${enc(c)}/evidence` },
  {
    name: "timeline",
    path: (c) => `/cases/${enc(c)}/timeline`,
    prepare: async (page) => {
      const row = page.getByRole("row").nth(3);
      if (await row.isVisible().catch(() => false)) {
        await row.click();
        await page.waitForTimeout(600);
      }
    },
  },
  { name: "findings", path: (c) => `/cases/${enc(c)}/findings` },
  { name: "graph", path: (c) => `/cases/${enc(c)}/graph` },
  { name: "memory", path: (c) => `/cases/${enc(c)}/memory` },
  { name: "iocs", path: (c) => `/cases/${enc(c)}/iocs` },
  { name: "reports", path: (c) => `/cases/${enc(c)}/reports` },
  { name: "custody", path: (c) => `/cases/${enc(c)}/custody` },
];

async function main(): Promise<void> {
  mkdirSync(OUT, { recursive: true });
  const stack = await startStack({ reuseBuild: true });
  const browser = await chromium.launch();
  try {
    for (const scheme of ["light", "dark"] as const) {
      const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: scheme, reducedMotion: "reduce" });
      const page = await ctx.newPage();
      await page.goto(`${stack.webUrl}/login`);
      await page.waitForLoadState("networkidle");
      if (scheme === "light") await page.screenshot({ path: join(OUT, "login.png") });
      await page.getByLabel("Username").fill(stack.users.alice.username);
      await page.getByLabel("Password").fill(stack.users.alice.password);
      await page.getByRole("button", { name: "Sign in" }).click();
      await page.waitForURL(/\/cases$/);
      for (const s of SHOTS) {
        await page.goto(`${stack.webUrl}${s.path(stack.caseId)}`);
        await page.waitForLoadState("networkidle");
        await page.waitForTimeout(800);
        if (s.prepare) await s.prepare(page);
        await page.screenshot({ path: join(OUT, `${s.name}${scheme === "dark" ? "-dark" : ""}.png`) });
        console.log(`captured ${s.name} (${scheme})`);
      }
      await ctx.close();
    }
  } finally {
    await browser.close();
    stopStack(stack);
  }
}

main().catch((err: unknown) => {
  console.error(err);
  process.exitCode = 1;
});
