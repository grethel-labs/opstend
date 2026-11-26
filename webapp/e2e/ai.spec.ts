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

test("managed compatible provider verifies and binds rotation to the reviewed revision", async ({ page }) => {
  const origin = "http://127.0.0.1:19080";
  const baseUrl = "https://10.0.0.4:8443/v1";
  const keys = {
    failed: "fixture-first-key",
    verified: "fixture-second-key",
    cancelled: "fixture-cancelled-key",
    rotated: "fixture-rotated-key",
    concurrent: "fixture-concurrent-key",
    stale: "fixture-stale-key",
  };
  const providerPath = "/api/ai/provider";
  function expectNoSecrets(body: string) {
    for (const key of Object.values(keys)) expect(body).not.toContain(key);
    expect(body).not.toContain("private:");
  }

  await page.goto(origin);
  await page.getByLabel("Admin token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await page.getByRole("link", { name: "AI", exact: true }).click();

  const change = page.getByRole("button", { name: "Change provider" });
  const compatible = page.getByRole("radio", { name: "OpenAI-compatible" });
  const save = page.getByRole("button", { name: "Save provider" });
  const cancel = page.getByRole("button", { name: "Cancel", exact: true });
  const url = page.getByLabel("Base URL");
  const key = page.getByLabel("API key", { exact: true });
  const newKey = page.getByLabel("New API key");
  const verifying = page.getByRole("status").filter({ hasText: "Verifying provider" });
  const choice = { option: "openai-compatible", base_url: baseUrl };

  async function view() {
    const response = await page.request.get(`${origin}/api/ai`);
    expect(response.status()).toBe(200);
    expectNoSecrets(await response.text());
    return response.json();
  }
  async function tick() {
    const response = await page.request.post(`${origin}/__browser_fixture__/compatible-tick`, {
      headers: { Origin: origin, "X-Browser-Fixture-Token": TOKEN },
    });
    expect(response.status()).toBe(200);
    expectNoSecrets(await response.text());
  }
  async function submit(expected: object) {
    const posted = page.waitForResponse(response => response.url() === origin + providerPath);
    await save.click();
    const response = await posted;
    expect(response.status()).toBe(200);
    expect(response.request().postDataJSON()).toEqual(expected);
    expectNoSecrets(await response.text());
  }

  await compatible.check();
  await expect(key).toHaveAttribute("type", "password");
  await url.fill(baseUrl);
  await key.fill(keys.failed);
  await submit({ ...choice, api_key: keys.failed });
  await expect(verifying).toBeVisible();
  await expect(page.getByText("no provider chosen")).toBeVisible();
  await expect(key).toHaveCount(0);
  expect(await view()).toMatchObject({ provider: null, pending_provider: { status: "pending" } });

  await tick();
  expect(await view()).toMatchObject({ provider: null, pending_provider: { status: "failed" } });
  await expect(page.getByRole("alert")).toContainText(
    "Provider verification failed (provider_validation_failed)", { timeout: 10000 },
  );
  await change.click();
  await compatible.check();
  await expect(key).toHaveValue("");
  await url.fill(baseUrl);
  await key.fill(keys.verified);
  await submit({ ...choice, api_key: keys.verified });
  await expect(verifying).toBeVisible();
  await tick();
  const verified = await view();
  expect(verified).toMatchObject({
    status: "scanned", pending_provider: null,
    provider: { id: choice.option, base_url: baseUrl },
    scanned: { models: ["fixture-alternate", "fixture-selected"] },
  });
  expect(verified.choice_id).toBeTruthy();
  await expect(page.getByText(baseUrl, { exact: true })).toBeVisible({ timeout: 10000 });
  await expect(page.getByRole("button", { name: /as initial model/ })).toHaveCount(2);
  await page.getByRole("button", { name: "Choose fixture-selected as initial model" }).click();
  await expect(page.getByText("Active model: fixture-selected")).toBeVisible();
  expect(await view()).toMatchObject({
    status: "ready", provider: { runtime_enabled: true }, active: { model: "fixture-selected" },
  });

  await change.click();
  await expect(compatible).toBeChecked();
  await expect(url).toHaveValue(baseUrl);
  await newKey.fill(keys.cancelled);
  await cancel.click();
  await expect(newKey).toHaveCount(0);
  expect(await view()).toMatchObject({ choice_id: verified.choice_id, pending_provider: null });

  await change.click();
  await expect(newKey).toHaveValue("");
  await newKey.fill(keys.rotated);
  await submit({ ...choice, api_key: keys.rotated, replace: true, expected_choice_id: verified.choice_id });
  await expect(verifying).toBeVisible();
  await expect(page.getByText("Active model: fixture-selected")).toBeVisible();
  expect(await view()).toMatchObject({ choice_id: verified.choice_id, pending_provider: { status: "pending" } });
  await tick();
  const rotated = await view();
  expect(rotated.choice_id).toBeTruthy();
  expect(rotated.choice_id).not.toBe(verified.choice_id);
  expect(rotated).toMatchObject({ pending_provider: null, active: { model: "fixture-selected" } });

  await expect(change).toBeEnabled({ timeout: 10000 });
  await change.click();
  await newKey.fill(keys.stale);
  const session = await (await page.request.get(`${origin}/api/session`)).json();
  const update = (apiKey: string, id: string) => page.request.post(origin + providerPath, {
    headers: { Origin: origin, "X-CSRF-Token": session.csrf, "Idempotency-Key": id },
    data: { ...choice, api_key: apiKey, replace: true, expected_choice_id: rotated.choice_id },
  });
  const concurrent = await update(keys.concurrent, "compatible-concurrent-rotation");
  expect(concurrent.status()).toBe(200);
  expectNoSecrets(await concurrent.text());
  await tick();
  const current = await view();
  expect(current.choice_id).not.toBe(rotated.choice_id);

  const stale = await update(keys.stale, "compatible-stale-rotation");
  expect(stale.status()).toBe(422);
  expectNoSecrets(await stale.text());
  expect(await stale.json()).toMatchObject({ detail: { code: "choice_changed" } });
  expect(await view()).toMatchObject({ choice_id: current.choice_id, pending_provider: null });
  await expect(page.getByRole("alert")).toContainText(
    "The provider changed. Reopen Change provider to continue.", { timeout: 10000 },
  );
  await change.click();
  await expect(newKey).toHaveValue("");
  expectNoSecrets(await page.locator("body").innerText());
});
