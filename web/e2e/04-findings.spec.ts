import { casePath, expect, login, logout, test } from "./fixtures";

const TITLE = "Lateral movement WS01 -> FS01";

test.describe("findings review", () => {
  test("alice confirms, cannot approve her own, and bob approves", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/findings"));
    await page.getByRole("button", { name: new RegExp(TITLE) }).click();
    const detail = page.getByTestId("finding-detail");
    await expect(detail.getByRole("heading", { name: TITLE })).toBeVisible();
    await expect(detail.getByRole("button", { name: "Confirm" })).toBeDisabled();
    await detail
      .getByLabel(/Rationale/)
      .fill("4648 on WS01 followed by an NTLM type 3 logon and PSEXESVC on FS01.");
    await detail.getByRole("button", { name: "Confirm" }).click();
    await expect(detail.getByTestId("confirmed-by")).toContainText("alice");

    const approve = detail.getByRole("button", { name: "Approve" });
    await expect(approve).toBeDisabled();
    await expect(detail.getByTestId("gate-reason")).toContainText("You confirmed this finding");

    await logout(page);
    await login(page, stack.users.bob);
    await page.goto(casePath(stack, "/findings"));
    await page.getByRole("button", { name: new RegExp(TITLE) }).click();
    await expect(detail.getByTestId("confirmed-by")).toContainText("alice");
    await detail.getByLabel("Reviewer comment").fill("Independently reviewed the logon chain.");
    await detail.getByRole("button", { name: "Approve" }).click();
    await expect(detail.getByTestId("approved-by")).toContainText("bob");
    await expect(page.getByRole("heading", { name: /^approved \(1\)/ })).toBeVisible();
  });

  test("supporting events link to the timeline and filters narrow the list", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/findings"));
    await page.getByLabel("Severity").selectOption("critical");
    await expect(page.getByTestId("finding-item")).toHaveCount(1);
    await page.getByTestId("finding-item").click();
    await expect(page.getByTestId("finding-detail")).toContainText("mimikatz.exe");
    await page
      .getByTestId("finding-detail")
      .getByRole("link", { name: /^#\d+$/ })
      .first()
      .click();
    await page.waitForURL(/\/timeline\?event=\d+/);
    await expect(page.getByRole("dialog").getByRole("heading", { name: "Provenance" })).toBeVisible();
  });

  test("manual finding, hypothesis and task board", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/findings"));
    await page.getByRole("button", { name: "Manual finding" }).click();
    const dlg = page.getByRole("dialog", { name: "Manual finding" });
    await dlg.getByLabel("Title").fill("Credential dumping on WS01");
    await dlg.getByLabel("Description").fill("Prefetch and memory show mimikatz execution.");
    await dlg.getByLabel("Severity").selectOption("high");
    await dlg.getByLabel("ATT&CK techniques").fill("T1003.001");
    await dlg.getByLabel("Supporting event ids").fill("2");
    await dlg.getByRole("button", { name: "Propose finding" }).click();
    await expect(
      page.getByTestId("finding-detail").getByRole("heading", { name: "Credential dumping on WS01" }),
    ).toBeVisible();

    await page.getByRole("tab", { name: "Hypotheses" }).click();
    await page.getByLabel("Title").fill("Initial access via browser download");
    await page.getByLabel("Statement").fill("bob downloaded mimikatz from evil.example.com and ran it.");
    await page.getByLabel("Supporting event ids").fill("1, 2");
    await page.getByRole("button", { name: "Add hypothesis" }).click();
    await expect(page.getByRole("list", { name: /Supporting events for Initial access/ })).toContainText(
      "#1",
    );

    await page.getByRole("tab", { name: "Tasks" }).click();
    await page.getByLabel("Title").fill("Image FS01");
    await page.getByLabel("Assignee", { exact: true }).selectOption("bob");
    await page.getByRole("button", { name: "Add task" }).click();
    await page.getByRole("button", { name: "Move Image FS01 to In progress" }).click();
    await expect(
      page.getByRole("region", { name: /In progress/ }).getByText("Image FS01", { exact: true }),
    ).toBeVisible();
  });
});
