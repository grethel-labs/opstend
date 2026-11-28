import { expect, test } from "@playwright/test";

test.describe.configure({ mode: "serial" });

test("operations shows incidents and decisions, and a decision can be approved", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Betrieb" })).toBeVisible();
  await expect(page.getByText("Störungen")).toBeVisible();
  const decisions = page.locator("section", { has: page.getByRole("heading", { name: "Anstehende Entscheidungen" }) });
  const decision = decisions.locator(".item", { hasText: "Firmware 7.2.123 auf sw-werkstatt" });
  await expect(decision).toBeVisible();
  await decision.getByRole("button", { name: /Freigeben/ }).click();
  await expect(page.getByRole("dialog")).toContainText("Firmware auf sw-werkstatt installieren");
  await page.getByRole("button", { name: "Freigeben und ausführen" }).click();
  await expect(page).toHaveURL(/#\/jobs\//);
  await expect(page.locator(".pill", { hasText: "Erledigt" }).first()).toBeVisible({ timeout: 20_000 });
});

test("a guest can be snapshotted through a previewed job", async ({ page }) => {
  await page.goto("/#/infra?tab=guests");
  await page.getByRole("cell", { name: /^fotos/ }).click();
  await expect(page.getByRole("heading", { name: "fotos" })).toBeVisible();
  await page.getByRole("button", { name: "Snapshot" }).click();
  await page.getByRole("button", { name: "Vorschau erstellen" }).click();
  await expect(page.getByRole("dialog")).toContainText("Snapshot");
  await page.getByRole("button", { name: "Freigeben und ausführen" }).click();
  await expect(page.locator(".pill", { hasText: "Erledigt" }).first()).toBeVisible({ timeout: 20_000 });
});

test("the topology renders with excaliplant and elements are selectable", async ({ page }) => {
  await page.goto("/#/network/topology");
  const svg = page.locator(".topo svg");
  await expect(svg).toBeVisible({ timeout: 20_000 });
  await expect(svg).toContainText("sw-werkstatt");
  // excaliplant puts transparent hit areas over each element; click by position like a user.
  const box = await svg.locator("text", { hasText: "sw-werkstatt" }).first().boundingBox();
  if (!box) throw new Error("switch not drawn");
  await page.mouse.click(box.x + box.width / 2, box.y + box.height / 2);
  await expect(page.getByRole("link", { name: "Details öffnen" })).toBeVisible();
});

test("network insights join UniFi and Proxmox facts", async ({ page }) => {
  await page.goto("/#/network");
  await expect(page.getByText(/nutzt VLAN 40, aber sw-werkstatt Port 2 führt es nicht/)).toBeVisible();
  await expect(page.getByText(/läuft mit 100 statt 1000 Mbit\/s/)).toBeVisible();
});

test("path check explains why the guest network is blocked", async ({ page }) => {
  await page.goto("/#/network/path");
  await page.getByLabel("Von").selectOption({ label: "handy-tom (Client)" });
  await page.getByLabel("Nach").selectOption({ label: "medien (VM)" });
  await page.getByRole("button", { name: "Pfad prüfen" }).click();
  await expect(page.getByText("nicht erreichbar")).toBeVisible();
});

test("Zorec answers from live state without a language model", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Zorec fragen" }).click();
  await page.getByRole("button", { name: "Welche Updates gibt es?" }).click();
  await expect(page.locator(".msg").last()).toContainText("Updates verfügbar");
});

test("a service is proposed from a repository and validated", async ({ page }) => {
  await page.goto("/#/services/new");
  await page.getByRole("button", { name: "Beispiel laden" }).click();
  await expect(page.getByRole("heading", { name: "web" })).toBeVisible();
  await expect(page.getByText("Gib das Geheimnis API_TOKEN für web an")).toBeVisible();
  await page.getByRole("button", { name: "Vorschau erstellen" }).click();
  await expect(page.getByRole("dialog")).toContainText("bereitstellen");
});

test("theme toggles to dark and the app stays readable", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Darstellung wechseln" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  const bg = await page.evaluate(() => getComputedStyle(document.body).backgroundColor);
  expect(bg).not.toBe("rgb(243, 246, 245)");
});

test("updates are planned in waves that keep quorum", async ({ page }) => {
  await page.goto("/#/updates");
  await expect(page.getByRole("heading", { name: "Abgestimmter Rollout" })).toBeVisible();
  await expect(page.locator(".steps li").first()).toContainText(/canary/i);
});
