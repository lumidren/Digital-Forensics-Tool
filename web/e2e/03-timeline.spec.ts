import { casePath, expect, login, test } from "./fixtures";

test.describe("timeline explorer", () => {
  test.beforeEach(async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/timeline"));
    await expect(page.getByTestId("result-count")).toContainText("events");
  });

  test("full-text search, pivot filter and event detail", async ({ page }) => {
    await page.getByLabel("Full-text search").fill("mimikatz");
    await page.getByRole("button", { name: "Search", exact: true }).click();
    await expect(page).toHaveURL(/q=mimikatz/);
    await expect(page.getByTestId("result-count")).toHaveText(/^[1-9]\d* events/);
    const grid = page.getByRole("grid", { name: "Timeline events" });
    await expect(grid.getByRole("row").nth(1)).toContainText(/mimikatz/i);

    await grid.getByRole("button", { name: "WS01" }).first().click();
    await expect(page).toHaveURL(/host=WS01/);
    await expect(page.getByRole("list", { name: "Active filters" })).toContainText("Host:");

    await grid.getByRole("row").nth(1).dblclick();
    const drawer = page.getByRole("dialog");
    await expect(drawer.getByRole("heading", { name: "Provenance" })).toBeVisible();
    await expect(drawer.getByText("Evidence SHA-256")).toBeVisible();
    await expect(drawer.getByRole("heading", { name: /All attributes/ })).toBeVisible();
    await drawer.getByRole("button", { name: /^Filter on data_type = / }).click();
    await expect(page).toHaveURL(/dt=/);
  });

  test("histogram keyboard brushing sets a time range", async ({ page }) => {
    const hist = page.getByTestId("histogram");
    await hist.focus();
    await page.keyboard.press("Home");
    await page.keyboard.press("Shift+End");
    await expect(page.locator("#histogram-status")).toContainText("Selected");
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/from=\d+&to=\d+/);
    await expect(page.getByRole("list", { name: "Active filters" })).toContainText("From:");
    await page.getByRole("button", { name: /^Remove filter From/ }).click();
    await expect(page).not.toHaveURL(/from=/);
  });

  test("attribute filter narrows to logon events", async ({ page }) => {
    await page.getByLabel("Attribute name").fill("event_identifier");
    await page.getByLabel("Attribute value").fill("4624");
    await page.getByRole("button", { name: "Add attribute filter" }).click();
    await expect(page).toHaveURL(/attr=event_identifier%3D4624/);
    await expect(page.getByTestId("result-count")).toHaveText(/^1 events/);
  });

  test("bookmarks the selected event with the keyboard", async ({ page }) => {
    await page.getByLabel("Full-text search").fill("PSEXESVC");
    await page.keyboard.press("Enter");
    await expect(page.getByTestId("result-count")).toHaveText(/^1 events/);
    await page.locator("body").click({ position: { x: 5, y: 5 } });
    await page.keyboard.press("j");
    await expect(page.getByRole("row", { selected: true })).toContainText("PSEXESVC");
    await page.keyboard.press("b");
    await expect(page.getByText(/Bookmarked event \d+/)).toBeVisible();
    await page.getByRole("tab", { name: "Bookmarks" }).click();
    await expect(
      page.getByRole("list", { name: "Bookmarked events" }).getByRole("button").first(),
    ).toBeVisible();
    await expect(
      page.getByRole("row", { selected: true }).getByRole("img", { name: "Bookmarked" }),
    ).toBeVisible();
  });

  test("saves a view and exports CSV", async ({ page }) => {
    await page.getByLabel("Full-text search").fill("explicit");
    await page.keyboard.press("Enter");
    await page.getByRole("button", { name: "Save view" }).click();
    await page.getByRole("dialog").getByLabel("Name").fill("Explicit credentials");
    await page.getByRole("dialog").getByRole("button", { name: "Save" }).click();
    await page.getByRole("tab", { name: "Views" }).click();
    await expect(page.getByRole("list", { name: "Saved views" })).toContainText("Explicit credentials");

    await page.getByRole("button", { name: "Export" }).click();
    const download = page.waitForEvent("download");
    await page.getByRole("menuitem", { name: "CSV" }).click();
    expect((await download).suggestedFilename()).toMatch(/-timeline\.csv$/);
  });
});
