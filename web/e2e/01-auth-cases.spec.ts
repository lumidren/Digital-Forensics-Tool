import { casePath, expect, login, logout, test } from "./fixtures";

test.describe("authentication", () => {
  test("rejects bad credentials and signs in", async ({ page, stack }) => {
    await page.goto("/login");
    await page.getByLabel("Username").fill("alice");
    await page.getByLabel("Password").fill("definitely-wrong-password");
    await page.getByRole("button", { name: "Sign in" }).click();
    await expect(page.locator("#login-error")).toHaveText("Invalid username or password.");

    await page.getByLabel("Password").fill(stack.users.alice.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForURL(/\/cases$/);
    await expect(page.getByRole("heading", { level: 1, name: "Cases" })).toBeVisible();
    await expect(page.getByRole("link", { name: stack.caseId })).toBeVisible();
  });

  test("keeps the token in sessionStorage only and clears it on logout", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    const stored = await page.evaluate(() => ({
      session: sessionStorage.getItem("veritas.session"),
      local: JSON.stringify(localStorage),
    }));
    expect(stored.session).toContain("token");
    expect(stored.local).not.toContain("eyJ");
    await logout(page);
    expect(await page.evaluate(() => sessionStorage.getItem("veritas.session"))).toBeNull();
    await page.goto(casePath(stack));
    await page.waitForURL(/\/login\?next=/);
  });

  test("redirects unauthenticated visitors to login with a return path", async ({ page, stack }) => {
    await page.goto(casePath(stack, "/timeline"));
    await page.waitForURL(/\/login\?next=%2Fcases%2F/);
    await page.getByLabel("Username").fill(stack.users.alice.username);
    await page.getByLabel("Password").fill(stack.users.alice.password);
    await page.getByRole("button", { name: "Sign in" }).click();
    await page.waitForURL(/\/timeline$/);
  });
});

test.describe("cases", () => {
  test("creates a case and opens its dashboard", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.getByRole("button", { name: "New case" }).click();
    const dialog = page.getByRole("dialog", { name: "New case" });
    await dialog.getByLabel("Name").fill("E2E intrusion triage");
    await dialog.getByLabel("Description").fill("Created by the end-to-end suite");
    await dialog.getByRole("button", { name: "Create case" }).click();
    await page.waitForURL(/\/cases\/C-[0-9]{8}-[0-9A-F]{6}$/);
    await expect(page.getByRole("heading", { level: 1, name: "E2E intrusion triage" })).toBeVisible();
    await expect(page.getByText("your role: lead")).toBeVisible();
    await expect(page.getByText("Custody entries")).toBeVisible();
  });

  test("shows the seeded case dashboard with counts and findings", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack));
    await expect(page.getByRole("heading", { level: 1, name: stack.caseName })).toBeVisible();
    await expect(page.getByText("Timeline events")).toBeVisible();
    await expect(page.getByTestId("state-proposed")).not.toHaveText("0");
    await expect(page.getByRole("heading", { name: "Processing queue" })).toBeVisible();
  });
});
