import { casePath, expect, login, seriousViolations, test } from "./fixtures";

const CASE_PAGES = [
  "",
  "/evidence",
  "/timeline",
  "/memory",
  "/graph",
  "/findings",
  "/iocs",
  "/reports",
  "/custody",
];

test.describe("accessibility (axe, WCAG 2.2 AA)", () => {
  test("login page", async ({ page }) => {
    await page.goto("/login");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
  });

  test("every application page in light and dark themes", async ({ page, stack }) => {
    test.setTimeout(180_000);
    await login(page, stack.users.admin);
    const pages = [
      "/cases",
      ...CASE_PAGES.map((p) => casePath(stack, p)),
      casePath(stack, `/evidence/${stack.evidenceId}`),
      "/admin",
    ];
    for (const scheme of ["light", "dark"] as const) {
      await page.emulateMedia({ colorScheme: scheme, reducedMotion: "reduce" });
      for (const path of pages) {
        await page.goto(path);
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await page.waitForLoadState("networkidle");
        const v = await seriousViolations(page);
        expect(v, `${scheme} ${path}`).toEqual([]);
      }
    }
  });

  test("dialogs, drawer and palette", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/timeline"));
    await page.keyboard.press("Control+k");
    await expect(page.getByRole("dialog", { name: "Command palette" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press("Escape");
    await page.keyboard.press("?");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
    await page.keyboard.press("Escape");
    await page.getByRole("grid", { name: "Timeline events" }).getByRole("row").nth(1).dblclick();
    await expect(page.getByRole("dialog").getByRole("heading", { name: "Provenance" })).toBeVisible();
    expect(await seriousViolations(page)).toEqual([]);
  });

  test("mobile width (360 px) has no horizontal page overflow", async ({ page, stack }) => {
    await page.setViewportSize({ width: 360, height: 780 });
    await login(page, stack.users.alice);
    const paths = [
      "/cases",
      ...CASE_PAGES.map((p) => casePath(stack, p)),
      casePath(stack, `/evidence/${stack.evidenceId}`),
    ];
    for (const path of paths) {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(overflow, path).toBeLessThanOrEqual(0);
    }
  });
});

test.describe("keyboard-only main flow", () => {
  test("sign in, navigate, search, inspect and review without a mouse", async ({ page, stack }) => {
    await page.goto("/login");
    await page.keyboard.type(stack.users.alice.username);
    await page.keyboard.press("Tab");
    await page.keyboard.type(stack.users.alice.password);
    await page.keyboard.press("Enter");
    await page.waitForURL(/\/cases$/);

    // Skip link is the first tab stop and moves focus to main.
    await page.keyboard.press("Tab");
    await expect(page.getByRole("link", { name: "Skip to main content" })).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(page.locator("#main")).toBeFocused();

    // Command palette opens the case.
    await page.keyboard.press("Control+k");
    await page.keyboard.type(stack.caseName);
    await page.keyboard.press("Enter");
    await page.waitForURL(new RegExp(`/cases/${stack.caseId}$`));

    // g t -> timeline, / focuses search.
    await page.keyboard.press("g");
    await page.keyboard.press("t");
    await page.waitForURL(/\/timeline/);
    await expect(page.getByTestId("result-count")).toContainText("events");
    await page.keyboard.press("/");
    await expect(page.getByLabel("Full-text search")).toBeFocused();
    await page.keyboard.type("mimikatz");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/q=mimikatz/);
    // Escape leaves the search field so table shortcuts apply again.
    await page.keyboard.press("Escape");
    await expect(page.getByLabel("Full-text search")).not.toBeFocused();
    await page.keyboard.press("j");
    await page.keyboard.press("Enter");
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByRole("heading", { name: "Provenance" })).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(drawer).toBeHidden();

    // g f -> findings, j selects the first finding.
    await page.keyboard.press("g");
    await page.keyboard.press("f");
    await page.waitForURL(/\/findings/);
    await expect(page.getByTestId("finding-item").first()).toBeVisible();
    await page.keyboard.press("j");
    await expect(page.getByTestId("finding-detail")).toBeVisible();
    await expect(page.getByTestId("finding-item").first()).toBeFocused();

    // ? opens the shortcut sheet; g c returns to the case list.
    await page.keyboard.press("?");
    await expect(page.getByRole("dialog", { name: "Keyboard shortcuts" })).toBeVisible();
    await page.keyboard.press("Escape");
    await page.keyboard.press("g");
    await page.keyboard.press("c");
    await page.waitForURL(/\/cases$/);
  });
});
