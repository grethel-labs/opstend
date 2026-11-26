import { expect, test } from "@playwright/test";

const TOKEN = "browser-test-token-0123456789abcdefghijklmnopqrstuvwxyz";
const ORIGIN = "http://localhost:19080";

test("initial provider uses references, scoped scans and explicit model choice", async ({ page, context }) => {
  const externalRequests: string[] = [];
  await context.route("**/*", route => {
    if (new URL(route.request().url()).origin === ORIGIN) return route.continue();
    externalRequests.push(route.request().url());
    return route.abort();
  });
  await page.goto("/");
  await page.getByLabel("Admin token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("link", { name: "AI", exact: true }).click();

  const native = page.getByRole("radio", { name: "Ollama (cloud models)", exact: true });
  const cloud = page.getByRole("radio", { name: "Ollama Cloud (API key)", exact: true });
  await expect(native).toBeDisabled();
  await expect(native.locator("../..")).toContainText("unavailable (");
  await expect(page.getByRole("button", { name: "Queue model scan" })).toHaveCount(0);
  await expect(page.getByText('<img src=x onerror="window.aiSourceXss=1">', { exact: true })).toBeVisible();
  await expect(page.locator('img[onerror*="aiSourceXss"]')).toHaveCount(0);

  const session = await (await page.request.get("/api/session")).json();
  const refused = await page.request.post("/api/ai/provider", {
    headers: {
      "X-CSRF-Token": session.csrf,
      "Idempotency-Key": "browser-native-refusal",
      Origin: ORIGIN,
    },
    data: { option: "ollama-cloud" },
  });
  expect(refused.status()).toBe(422);
  expect(await refused.json()).toMatchObject({ detail: { code: "method_unavailable" } });

  const providerRequests: unknown[] = [];
  page.on("request", request => {
    if (new URL(request.url()).pathname === "/api/ai/provider") providerRequests.push(request.postDataJSON());
  });
  await cloud.check();
  const reference = page.getByLabel("API key reference");
  const save = page.getByRole("button", { name: "Save provider" });
  await reference.fill("fixture-raw-value");
  await save.click();
  await expect(page.getByRole("alert")).toContainText("Enter an env: or file: key reference.");
  expect(providerRequests).toEqual([]);
  await reference.fill("env:STEWARD_AI_FIXTURE_KEY");
  const savedResponse = page.waitForResponse(response => response.url().endsWith("/api/ai/provider"));
  await save.click();
  const saved = await savedResponse;
  expect(saved.status()).toBe(200);
  expect(saved.request().headers()["idempotency-key"]).toBeTruthy();
  expect(saved.request().headers()["x-csrf-token"]).toBe(session.csrf);
  expect(providerRequests).toEqual([{ option: "ollama-cloud-api", key_ref: "env:STEWARD_AI_FIXTURE_KEY" }]);
  await expect(save).toHaveCount(0);
  await expect(page.getByText(/Provider runtime is disabled/)).toBeVisible();

  const scanResponse = page.waitForResponse(response => response.url().endsWith("/api/ai/scan"));
  await page.getByRole("button", { name: "Queue model scan" }).click();
  const scan = await scanResponse;
  expect(scan.status()).toBe(202);
  expect(scan.request().headers()["idempotency-key"]).toBeTruthy();
  expect(scan.request().headers()["x-csrf-token"]).toBe(session.csrf);
  const queued = await scan.json();
  expect(queued).toMatchObject({ kind: "scan", state: "pending" });
  const requests = page.getByRole("list", { name: "Recent AI requests" });
  await expect(requests).toContainText("scan — queued (pending)");
  await expect(page.getByRole("button", { name: /as initial model/ })).toHaveCount(0);
  const view = await (await page.request.get("/api/ai")).json();
  expect(view).toMatchObject({
    provider: { id: "ollama-cloud-api", runtime_enabled: false },
    active: null, scanned: null, auto_selection: false,
  });

  const finished = await page.request.post("/__browser_fixture__/finish-ai-scan", {
    headers: { Origin: ORIGIN, "X-Browser-Fixture-Token": TOKEN },
  });
  expect(finished.status()).toBe(200);
  expect(await finished.json()).toMatchObject([{ id: queued.id, kind: "scan", state: "done" }]);
  const suggested = page.getByRole("button", { name: "Choose deepseek-v4.1-flash as initial model" });
  const model = page.getByRole("button", { name: "Choose fixture-model:cloud as initial model" });
  await expect(suggested.locator("..")).toContainText("Suggested model", { timeout: 10000 });
  await expect(page.getByRole("button", { name: /as initial model/ })).toHaveCount(2);
  await expect(page.getByText("Selected model: –")).toBeVisible();

  const initialResponse = page.waitForResponse(response => response.url().endsWith("/api/ai/initial-model"));
  await model.click();
  const initial = await initialResponse;
  expect(initial.status()).toBe(200);
  expect(initial.request().headers()["idempotency-key"]).toBeTruthy();
  expect(initial.request().headers()["x-csrf-token"]).toBe(session.csrf);
  expect(initial.request().postDataJSON()).toEqual({ model: "fixture-model:cloud" });
  await expect(requests).toContainText("initial_check — queued (pending)");
  await expect(page.getByText("Selected model: fixture-model:cloud")).toBeVisible();
  await expect(page.getByText(/Provider runtime is disabled/)).toBeVisible();
  expect(externalRequests).toEqual([]);
});
