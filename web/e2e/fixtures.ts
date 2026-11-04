import AxeBuilder from "@axe-core/playwright";
import { expect, test as base, type Page } from "@playwright/test";
import { readState, type StackState, type UserCreds } from "./stack";

export interface Fixtures {
  stack: StackState;
}

export const test = base.extend<Fixtures>({
  stack: async ({}, provide) => {
    await provide(readState());
  },
  baseURL: async ({}, provide) => {
    await provide(readState().webUrl);
  },
});

export { expect };

export async function login(page: Page, user: UserCreds): Promise<void> {
  await page.goto("/login");
  await page.getByLabel("Username").fill(user.username);
  await page.getByLabel("Password").fill(user.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.waitForURL(/\/cases$/);
}

export async function logout(page: Page): Promise<void> {
  await page.getByRole("button", { name: /Account menu/ }).click();
  await page.getByRole("menuitem", { name: "Sign out" }).click();
  await page.waitForURL(/\/login/);
}

export function casePath(stack: StackState, sub = ""): string {
  return `/cases/${encodeURIComponent(stack.caseId)}${sub}`;
}

/** WCAG 2.2 AA axe scan; returns serious and critical violations only. */
export async function seriousViolations(
  page: Page,
): Promise<{ id: string; impact: string | null | undefined; nodes: string[] }[]> {
  const res = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"])
    .analyze();
  return res.violations
    .filter((v) => v.impact === "serious" || v.impact === "critical")
    .map((v) => ({ id: v.id, impact: v.impact, nodes: v.nodes.slice(0, 5).map((n) => n.target.join(" ")) }));
}
