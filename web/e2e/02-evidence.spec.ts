import { createHash } from "node:crypto";
import { casePath, expect, login, test } from "./fixtures";

test.describe("evidence", () => {
  test("uploads evidence with progress and shows processing status", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/evidence"));
    await expect(page.getByTestId("ws-status").first()).toHaveText("connected");
    const body = Buffer.from("Security event export\n".repeat(4096));
    const sha = createHash("sha256").update(body).digest("hex");
    await page
      .getByLabel("Evidence file")
      .setInputFiles({ name: "export.log", mimeType: "text/plain", buffer: body });
    await page.getByLabel("Kind").selectOption("file");
    await page.getByLabel("Expected SHA-256 (optional)").fill(sha);
    await page.getByLabel("Source timezone").fill("Europe/Berlin");
    await page.getByLabel("Clock skew (ms)").fill("1500");
    await page.getByLabel("Host").fill("WS02");
    await page.getByRole("button", { name: "Upload and hash" }).click();
    const progress = page.getByTestId("upload-progress");
    await expect(progress.getByRole("progressbar")).toBeVisible();
    await expect(progress.getByRole("status")).toContainText(/Stored as EV-[0-9A-F]+; job J-/);
    const row = page.getByRole("row", { name: /export\.log/ });
    await expect(row).toBeVisible();
    const job = page.getByTestId("job").filter({ hasText: "export.log" });
    await expect(job).toBeVisible();
    await expect(job.getByTestId("job-state")).toHaveText(/done|failed/, { timeout: 45_000 });
    await expect(job.getByRole("progressbar").first()).toBeVisible();
  });

  test("rejects an upload whose hash does not match", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, "/evidence"));
    await page.getByLabel("Evidence file").setInputFiles({
      name: "tampered.bin",
      mimeType: "application/octet-stream",
      buffer: Buffer.from("abc"),
    });
    await page.getByLabel("Expected SHA-256 (optional)").fill("0".repeat(64));
    await page.getByRole("button", { name: "Upload and hash" }).click();
    await expect(page.getByTestId("upload-progress").getByRole("alert")).toContainText("hash mismatch");
  });

  test("shows hashes, verifies integrity and browses bytes", async ({ page, stack }) => {
    await login(page, stack.users.alice);
    await page.goto(casePath(stack, `/evidence/${stack.evidenceId}`));
    await expect(page.getByRole("heading", { level: 1, name: "triage-WS01.bin" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Ingest ledger entry" })).toBeVisible();
    await expect(page.getByText("evidence triage-WS01.bin stored")).toBeVisible();
    await page.getByRole("button", { name: "Verify integrity" }).click();
    await expect(page.getByTestId("integrity-verdict")).toContainText("PASS");

    await expect(page.getByText(/recorded as a signed/)).toBeVisible();
    const hex = page.getByRole("table", { name: "Evidence bytes" });
    await expect(hex.getByRole("row").nth(1)).toContainText("00000000");
    await expect(hex.getByRole("row").nth(1)).toContainText("4d 5a 90 00");
    await expect(hex.getByRole("row").nth(1)).toContainText("MZ..Veritas");
    await page.getByLabel("Go to offset").fill("0x1000");
    await page.getByRole("button", { name: "Go", exact: true }).click();
    await expect(page.getByTestId("hex-position")).toContainText("cursor 0x00001000 (4096)");
    await expect(hex.getByRole("row", { name: /^00001000/ })).toBeVisible();
    await page.getByRole("button", { name: "End of object" }).click();
    await expect(page.getByTestId("hex-position")).toContainText("cursor 0x");
    await page.getByLabel("Go to offset").fill("nonsense");
    await page.getByRole("button", { name: "Go", exact: true }).click();
    await expect(page.getByRole("alert").filter({ hasText: "Enter an offset" })).toBeVisible();

    await page.goto(casePath(stack, `/custody?evidence=${stack.evidenceId}`));
    await page.getByLabel("Kind").selectOption("access");
    await expect(page.getByTestId("custody-row").filter({ hasText: "hex view" }).first()).toBeVisible();
  });
});
