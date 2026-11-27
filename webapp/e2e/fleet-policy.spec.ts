import { expect, test } from "@playwright/test";

const TOKEN = "browser-test-token-0123456789abcdefghijklmnopqrstuvwxyz";
const ORIGIN = "http://localhost:19081";

test.use({ baseURL: ORIGIN });

test("exact fleet approval survives reload and reports partial target adoption", async ({ page, context }) => {
  await page.goto("/");
  await page.getByLabel("Admin token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Fleet policy", exact: true })).toBeVisible();
  expect((await page.request.get("/api/config")).status()).toBe(404);
  const targets = page.getByRole("checkbox");
  await expect(targets).toHaveCount(2);
  await targets.nth(0).check();
  await targets.nth(1).check();
  await page.getByRole("button", { name: "Preview selected targets" }).click();
  await expect(page.getByRole("heading", { name: "Policy preview" })).toBeVisible();
  await expect(page.getByText("env:FLEET_FIXTURE_REFERENCE", { exact: false }).first()).toBeVisible();
  await expect(page.getByText("local unknown", { exact: false })).toBeVisible();

  const other = await context.newPage();
  await other.goto("/");
  await other.getByRole("button", { name: "Load current policy" }).click();
  await expect(other.getByLabel("Fleet policy (JSON)")).toHaveValue(/FLEET_FIXTURE_REFERENCE/);
  const stage = other.waitForResponse((r) => r.url().endsWith("/revisions") && r.request().method() === "POST");
  await other.getByRole("button", { name: "Stage policy" }).click();
  expect((await stage).ok()).toBe(true);
  await other.close();

  await page.getByRole("button", { name: "Approve reviewed revision" }).click();
  await expect(page.getByRole("alert")).toContainText("Review the current revision again");
  await expect(page.getByRole("heading", { name: "Policy preview" })).toHaveCount(0);
  await expect(targets.nth(0)).toBeChecked();
  await expect(targets.nth(1)).toBeChecked();
  await page.getByRole("button", { name: "Preview selected targets" }).click();
  const submitted = page.waitForResponse((r) => r.url().endsWith("/approve") && r.ok());
  await page.getByRole("button", { name: "Approve reviewed revision" }).click();
  const approval = await (await submitted).json();
  await expect(page.getByRole("cell", { name: "pending", exact: true })).toHaveCount(2);

  const adopted = await page.request.post("/__browser_fixture__/fleet/adopt", {
    headers: { Origin: ORIGIN, "X-Browser-Fixture-Token": TOKEN },
    params: { approval: approval.id, digest: approval.digest },
  });
  expect((await adopted.json()).status).toBe("applied");
  await page.reload();
  await expect(page.getByRole("combobox", { name: "Approval" })).toHaveValue(approval.id);
  await expect(page.getByRole("cell", { name: "applied", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "pending", exact: true })).toBeVisible();
});
