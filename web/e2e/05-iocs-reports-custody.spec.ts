import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { casePath, expect, login, test } from "./fixtures";

test.describe("IOCs", () => {
  test("imports indicators, sweeps the timeline and downloads STIX", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/iocs"));
    await page
      .getByLabel("Indicators", { exact: true })
      .fill("mimikatz.exe\nipv4:10.0.0.66\nevil.example.com");
    await page.getByRole("button", { name: "Import" }).click();
    await expect(page.getByText(/Imported 3 new of 3 indicators/)).toBeVisible();
    await expect(page.getByTestId("ioc-row")).toHaveCount(3);
    await page.getByRole("button", { name: "Sweep timeline" }).click();
    await expect(page.getByTestId("sweep-summary")).toContainText(/Sweep complete: [1-9]\d* hits?/);
    const hits = await page.getByTestId("ioc-hits").allTextContents();
    expect(hits.map(Number).some((n) => n > 0)).toBe(true);
    const dl = page.waitForEvent("download");
    await page.getByRole("button", { name: "STIX bundle" }).click();
    const file = await dl;
    const bundle = JSON.parse(readFileSync((await file.path()) ?? "", "utf8")) as { type: string };
    expect(bundle.type).toBe("bundle");
  });
});

test.describe("reports", () => {
  test("generates a signed report whose download matches its SHA-256", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/reports"));
    await page.getByLabel("Limitations").fill("Volume shadow copies were not examined.");
    await page.getByRole("button", { name: "Add limitation" }).click();
    await page.getByRole("button", { name: "Generate and sign" }).click();
    const created = page.getByTestId("report-created");
    await expect(created).toContainText(/Report R-[0-9a-f]{12}/, { timeout: 45_000 });
    const row = page.getByTestId("report-row").first();
    await expect(row).toContainText("Signer key");
    await expect(row.getByText(/^[0-9a-f]{32}$/).first()).toBeVisible();
    const listed = (await row.locator("dd").first().textContent())?.trim() ?? "";
    expect(listed).toMatch(/^[0-9a-f]{64}$/);

    const dl = page.waitForEvent("download");
    await row.getByRole("button", { name: /Download document/ }).click();
    const file = await dl;
    const digest = createHash("sha256")
      .update(readFileSync((await file.path()) ?? ""))
      .digest("hex");
    expect(digest).toBe(listed);
    await expect(page.getByTestId("hash-check")).toContainText("Hash matches");

    const sig = page.waitForEvent("download");
    await row.getByRole("button", { name: /Download signature/ }).click();
    const sigDoc = JSON.parse(readFileSync((await (await sig).path()) ?? "", "utf8")) as {
      report_sha256: string;
      signature_ed25519: string;
    };
    expect(sigDoc.report_sha256).toBe(listed);
    expect(sigDoc.signature_ed25519).toMatch(/^[0-9a-f]{128}$/);
  });
});

test.describe("custody", () => {
  test("verifies the chain, anchors the head and exports signed JSON", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/custody"));
    await page.getByRole("button", { name: "Verify chain" }).click();
    await expect(page.getByTestId("custody-verdict")).toContainText("PASS");
    await page.getByRole("button", { name: "Anchor head" }).click();
    await expect(page.getByText(/Ledger head #\d+ anchored/)).toBeVisible();
    await page.getByLabel("Kind").selectOption("ingest");
    await expect(page.getByTestId("custody-row").first()).toContainText("ingest");

    const dl = page.waitForEvent("download");
    await page.getByRole("button", { name: "Export signed JSON" }).click();
    const file = await dl;
    expect(file.suggestedFilename()).toBe(`${stack.caseId}-custody.json`);
    const doc = JSON.parse(readFileSync((await file.path()) ?? "", "utf8")) as {
      format: string;
      entries: unknown[];
    };
    expect(doc.format).toBe("veritas-custody");
    expect(doc.entries.length).toBeGreaterThan(3);
    await expect(page.getByTestId("verify-command")).toHaveText(
      `veritas-verify export ${stack.caseId}-custody.json`,
    );
  });
});

test.describe("administration", () => {
  test("admin verifies the audit chain and store integrity", async ({ page, stack }) => {
    await login(page, stack.users.admin);
    await page.goto("/admin");
    await expect(page.getByRole("table", { name: "Users" })).toContainText("alice");
    await page.getByRole("tab", { name: "Audit log" }).click();
    await expect(page.getByRole("table", { name: "Audit log" })).toContainText("auth.login");
    await page.getByRole("button", { name: "Verify audit chain" }).click();
    await expect(page.getByTestId("audit-verdict")).toContainText("PASS");
    await page.getByRole("tab", { name: "Store" }).click();
    await page.getByRole("button", { name: "Verify store integrity" }).click();
    await expect(page.getByTestId("store-verdict")).toContainText("PASS");
    await page.getByRole("tab", { name: "Keys" }).click();
    await expect(page.getByRole("table", { name: "Signing key registry" })).toContainText("alice");
  });

  test("non-admins cannot use the admin console", async ({ page, stack }) => {
    await login(page, stack.users.bob);
    await page.goto("/admin");
    await expect(
      page.getByRole("alert").filter({ hasText: "requires a global administrator" }),
    ).toBeVisible();
  });
});
