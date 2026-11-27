import { expect, test } from "@playwright/test";

const TOKEN = "browser-fleet-power-fixture-0123456789abcdefghijklmnopqrstuvwxyz";
const ORIGIN = "http://localhost:19082";

test.use({ baseURL: ORIGIN });

test("an authenticated operator reviews, approves and tracks one guest start across reload", async ({ page, request }) => {
  expect((await request.get("/api/fleet/commands")).status()).toBe(401);
  await page.goto("/");
  await page.getByLabel("Admin token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  const power = page.getByRole("region", { name: "Guest power" });
  const guests = power.getByLabel("Guest to start");
  await expect(guests.getByRole("option", { name: /power-fixture · VM 190 on browser-pve/ })).toHaveCount(1);
  await guests.selectOption({ index: 1 });
  await power.getByRole("button", { name: "Preview guest start" }).click();
  await expect(power.getByRole("status")).toHaveText("Waiting for the target to prepare a preview");
  await expect(power.getByRole("button", { name: "Approve guest start" })).toHaveCount(0);
  const selected = power.getByLabel("Guest command");
  const commandId = await selected.inputValue();
  expect(commandId).toMatch(/^[0-9a-f]{32}$/);

  async function tick(phase: string) {
    const response = await page.request.post("/__browser_fixture__/fleet/power-tick", {
      headers: { Origin: ORIGIN, "X-Browser-Fixture-Token": TOKEN },
    });
    expect(response.ok()).toBe(true);
    expect(await response.json()).toEqual({ phase });
  }

  await tick("prepare");
  await expect(power.getByRole("status")).toHaveText("Ready for approval");
  await expect(power.getByText("stopped", { exact: true })).toBeVisible();
  const detail = await page.request.get(`/api/fleet/commands/${commandId}`);
  const command = await detail.json();
  expect(command.digest).toMatch(/^[0-9a-f]{64}$/);
  expect(command).not.toHaveProperty("pve_uid");
  expect((await page.request.post(`/api/fleet/commands/${commandId}/approve`, {
    headers: { Origin: ORIGIN, "Idempotency-Key": "no-csrf" },
    data: { digest: command.digest },
  })).status()).toBe(403);

  await power.getByRole("button", { name: "Approve guest start" }).click();
  await expect(power.getByRole("status")).toHaveText("Approved · waiting for the target");
  await tick("execute");
  await expect(power.getByRole("status")).toContainText("Native task accepted");
  await tick("reconcile");
  await expect(power.getByRole("status")).toHaveText("Start verified");

  await page.reload();
  await expect(selected).toHaveValue(commandId);
  await expect(power.getByRole("status")).toHaveText("Start verified");
  await expect(power.getByText("running", { exact: true })).toBeVisible();
});
