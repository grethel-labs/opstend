import { expect, test, type Page, type Route } from "@playwright/test";

const TOKEN = "browser-test-token-0123456789abcdefghijklmnopqrstuvwxyz";

async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("Admin token").fill(TOKEN);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
}

test("scanner observations traverse real Unix socket and API with bounded findings", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Vulnerabilities", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Vulnerabilities", exact: true })).toBeVisible();
  await expect(page.getByRole("status")).toContainText("Scan coverage is incomplete");
  await expect(page.getByText("CVE-2026-1234", { exact: true })).toBeVisible();
  await expect(page.getByText(/KEV available: listed/)).toBeVisible();
  await expect(page.getByText(/EPSS available: 42.00%/)).toBeVisible();
  await expect(page.getByText(/Context requested: KEV on, EPSS on/)).toBeVisible();
  await expect(page.getByText('<img src=x onerror="window.scannerXss=1">', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { scannerXss?: number }).scannerXss)).toBeUndefined();
  await page.getByRole("button", { name: "Next finding for openssl", exact: true }).click();
  await expect(page.getByText("CVE-2026-9999", { exact: true })).toBeVisible();
  await expect(page.getByText("No supplemental CVE evidence is stored for this finding; context is unknown or disabled.", { exact: true })).toBeVisible();
  await expect(page.getByText("CVE-2026-1234", { exact: true })).toHaveCount(0);
  await page.getByRole("button", { name: "All subjects", exact: true }).click();
  await expect(page.getByText("CVE-2026-1234", { exact: true })).toBeVisible();
});

test("a disabled scanner is shown as disabled with unknown coverage", async ({ page }) => {
  await login(page);
  await page.route(/\/api\/scans(?:\?.*)?$/, route => route.fulfill({ json: {
    snapshot_id: null, records: [], total: 0, next_offset: null, jobs: [],
    summary: { enabled: false, complete: false, stale: false, configuration_matches: false, counts: {} },
  }}));
  await page.getByRole("link", { name: "Vulnerabilities", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("Scanning is disabled. Coverage is unknown");
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByText("No stored subjects match this filter.", { exact: false })).toHaveCount(0);
});

test("real login, protected session, navigation and logout under production CSP", async ({ page, context }) => {
  const violations: string[] = [];
  page.on("console", message => {
    if (message.type() === "error" && /content security policy/i.test(message.text())) {
      violations.push(message.text());
    }
  });
  await page.goto("/");
  await expect(page).toHaveTitle("OpsTend Admin");
  await expect(page.locator(".product-mark")).toHaveJSProperty("naturalWidth", 64);
  await expect(page.getByText("by Grethel Labs", { exact: true })).toBeVisible();
  await expect(page.locator('link[rel="icon"]:not([media])')).toHaveAttribute("href", "/brand/opstend.svg");
  await page.getByLabel("Admin token").fill("wrong-token");
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await login(page);
  const productHome = page.getByRole("link", { name: "OpsTend home, by Grethel Labs" });
  await expect(productHome.getByText("by Grethel Labs", { exact: true })).toBeVisible();
  await expect(productHome.locator("img")).toHaveJSProperty("naturalWidth", 64);
  const zorec = page.getByRole("link", { name: "Zorec", exact: true });
  await expect(zorec).toHaveAttribute("href", "#/ai");
  await expect(zorec.locator("img")).toHaveJSProperty("naturalWidth", 64);
  await expect(zorec.locator("img")).toHaveJSProperty("currentSrc", new URL("/brand/zorec.svg?view=light-neutral#light-neutral", page.url()).href);
  await page.emulateMedia({ colorScheme: "dark" });
  await expect(productHome.locator("img")).toHaveJSProperty("currentSrc", new URL("/brand/opstend-dark.svg", page.url()).href);
  await expect(zorec.locator("img")).toHaveJSProperty("currentSrc", new URL("/brand/zorec.svg?view=dark-neutral#dark-neutral", page.url()).href);
  await expect(page.getByRole("alert")).toContainText("Observation gap");
  const session = (await context.cookies()).find(cookie => cookie.name.startsWith("__Host-"));
  expect(session?.httpOnly).toBe(true);
  expect(session?.secure).toBe(true);
  expect(session?.sameSite).toBe("Strict");
  await page.reload();
  await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
  await page.getByRole("link", { name: "Projects", exact: true }).click();
  await expect(page.getByRole("cell", { name: "notes", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Restart", exact: true })).toBeDisabled();
  await page.getByRole("button", { name: "Sign out", exact: true }).click();
  await expect(page.getByLabel("Admin token")).toBeVisible();
  expect((await page.request.get("/api/session")).status()).toBe(401);
  expect(violations).toEqual([]);
});

test("validation, diff, pending revision and concurrent-tab conflict use real API", async ({ page, context }) => {
  await login(page);
  await page.getByRole("link", { name: "Configuration", exact: true }).click();
  const editor = page.getByLabel("Configuration (YAML)");
  await expect(editor).toHaveValue(/schema_version: 1/);
  const original = await editor.inputValue();
  await editor.fill("invalid: [");
  await page.getByRole("button", { name: "Validate and show diff" }).click();
  await expect(page.getByRole("alert")).toBeVisible();
  await expect(page.getByRole("button", { name: "Save revision" })).toBeDisabled();

  const other = await context.newPage();
  await other.goto("/#/config");
  await expect(other.getByLabel("Configuration (YAML)")).toHaveValue(/schema_version: 1/);
  await other.getByLabel("Configuration (YAML)").fill(original.replace("memory_mb: 128", "memory_mb: 256"));
  await other.getByRole("button", { name: "Validate and show diff" }).click();
  await expect(other.getByRole("button", { name: "Save revision" })).toBeEnabled();

  await editor.fill(original.replace("memory_mb: 128", "memory_mb: 192"));
  await page.getByRole("button", { name: "Validate and show diff" }).click();
  await expect(page.getByRole("cell", { name: "projects[notes].resources.memory_mb", exact: true })).toBeVisible();
  await page.getByRole("textbox", { name: "Change note" }).fill("Browser acceptance test");
  await page.getByRole("button", { name: "Save revision" }).click();
  await expect(page.getByRole("status")).toContainText("pending");
  await expect(page.getByText("pending deployment", { exact: true })).toBeVisible();
  await other.getByRole("button", { name: "Save revision" }).click();
  await expect(other.getByRole("alert")).toContainText("Conflict");
  await other.close();
});

test("form fields and YAML share one draft, preserve comments and invalidate stale diffs", async ({ page }) => {
  await login(page);
  await page.getByRole("link", { name: "Configuration", exact: true }).click();
  const editor = page.getByLabel("Configuration (YAML)");
  await expect(editor).toHaveValue(/schema_version: 1/);
  await editor.fill("# Keep this operator note\n" + await editor.inputValue());
  await page.getByText("Form fields", { exact: true }).click();
  await page.getByLabel("notes memory (MiB)", { exact: true }).fill("224");
  await expect(editor).toHaveValue(/memory_mb: 224/);
  await expect(editor).toHaveValue(/# Keep this operator note/);
  await page.getByRole("button", { name: "Validate and show diff" }).click();
  await expect(page.getByRole("button", { name: "Save revision" })).toBeEnabled();
  await page.getByLabel("notes: allow automatic restart", { exact: true }).uncheck();
  await expect(page.getByRole("button", { name: "Save revision" })).toBeDisabled();
  await expect(editor).toHaveValue(/allow_restart: false/);
  await page.getByRole("button", { name: "Validate and show diff" }).click();
  await expect(page.getByRole("cell", { name: "projects[notes].maintenance.allow_restart", exact: true })).toBeVisible();
  await page.getByLabel("Enable scheduled vulnerability scans", { exact: true }).uncheck();
  await page.getByLabel("Maximum OSV requests per scan", { exact: true }).fill("500");
  await expect(editor).toHaveValue(/max_requests: 500/);
  await expect(page.getByRole("button", { name: "Save revision" })).toBeDisabled();
  await page.getByRole("button", { name: "Validate and show diff" }).click();
  await expect(page.getByRole("cell", { name: "scanning.enabled", exact: true })).toBeVisible();
  await editor.fill("broken: [");
  await expect(page.getByText(/Form fields need a valid configuration/)).toBeVisible();
});

test("backup evidence presents partial phases and escapes hostile text", async ({ page }) => {
  await login(page);
  await page.route("**/api/backups", route => route.fulfill({ json: {
    enabled: true, freshness: "fresh", generated_at: Date.now() / 1000,
    projects: [{ project: "notes", registered: true, capture_state: "exported", capture_id: "a".repeat(64),
      capture_created_at: Date.now() / 1000, capture_freshness: "fresh", config_revision: "b".repeat(64),
      worker_state: "failed", job_state: "queued", job_error: '<img src=x onerror="window.backupXss=1">',
      repository_id: "c".repeat(64), snapshot_id: "d".repeat(64), uploaded_at: Date.now() / 1000,
      integrity_checked_at: Date.now() / 1000, restored_bytes_at: null, application_drill_at: null,
      root_provenance: "executor_schedule", worker_provenance: "worker_reported" }],
  }}));
  await page.getByRole("link", { name: "Backups", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Backups", exact: true })).toBeVisible();
  await expect(page.getByRole("cell", { name: "notes", exact: true })).toBeVisible();
  await expect(page.getByText("Independent application drill: unknown")).toBeVisible();
  await expect(page.getByText('<img src=x onerror="window.backupXss=1">', { exact: false })).toBeVisible();
  expect(await page.evaluate(() => (window as Window & { backupXss?: number }).backupXss)).toBeUndefined();
});

const APPLY = "/api/config/apply";
const ORIGIN = "http://localhost:19080";

async function saveRevision(page: Page, yaml: string) {
  await page.getByLabel("Configuration (YAML)").fill(yaml);
  const validated = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/api/config/validate" && response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Validate and show diff", exact: true }).click();
  const validation = await validated;
  expect(validation.status()).toBe(200);
  const { revision } = await validation.json();
  expect(revision).toMatch(/^[a-f0-9]{64}$/);

  const saved = page.waitForResponse(response =>
    new URL(response.url()).pathname === "/api/config/revisions" && response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Save revision", exact: true }).click();
  const commit = await saved;
  expect(commit.status()).toBe(200);
  expect(await commit.json()).toEqual({ revision, pending: true });
  return revision as string;
}

function expectRevisions(page: Page, head: string, applied: string) {
  return expect(page.getByText(new RegExp(`Head\\s+${head}\\s*·\\s*applied\\s+${applied}`, "i"))).toBeVisible();
}

test("apply is bound to saved revisions and shows the durable outcome across polling and reload", async ({ page, context }) => {
  test.setTimeout(45_000);
  await login(page);
  await page.getByRole("link", { name: "Configuration", exact: true }).click();
  const editor = page.getByLabel("Configuration (YAML)");
  const plan = page.getByRole("region", { name: "Apply pending revision", exact: true });
  const apply = plan.getByRole("button", { name: "Apply on server", exact: true });
  const outcome = page.getByRole("region", { name: "Apply outcome", exact: true });
  await expect(editor).toHaveValue(/schema_version: 1/);
  const original = await editor.inputValue();
  const initial = await (await page.request.get("/api/config")).json();
  const applied: string = initial.applied;
  expect(applied).toMatch(/^[a-f0-9]{64}$/);
  const session = await page.request.get("/api/session");
  expect(session.status()).toBe(200);
  const { csrf, version } = await session.json();
  const jobs = async () => {
    const response = await page.request.get("/api/jobs");
    expect(response.status()).toBe(200);
    return (await response.json()).jobs;
  };
  const initialJobs = await jobs();

  const projectMemory = /^    memory_mb: \d+$/m;
  expect(original).toMatch(projectMemory);
  const unsupported = await saveRevision(page, original.replace(projectMemory, "    memory_mb: 384"));
  await expectRevisions(page, unsupported, applied);
  await expect(plan).toContainText("./opstend deploy");
  await expect(apply).toHaveCount(0);
  const unsupportedResponse = await page.request.post(APPLY, {
    data: { head: unsupported, applied },
    headers: { Origin: ORIGIN, "X-CSRF-Token": csrf, "Idempotency-Key": "browser-unsupported" },
  });
  expect(unsupportedResponse.status()).toBe(422);
  expect(await jobs()).toEqual(initialJobs);
  await expect(editor).toHaveValue(/memory_mb: 384/);

  // The earlier concurrent-save scenario may have left a memory change pending.
  const supportedYaml = original.replace(projectMemory, "    memory_mb: 128")
    .replace("allow_restart: true", "allow_restart: false");
  const pending = await saveRevision(page, supportedYaml);
  await expectRevisions(page, pending, applied);
  await expect(plan).toContainText(pending);
  await expect(plan).toContainText(applied);
  await expect(plan).toContainText(version);
  await expect(plan).toContainText("projects");
  await expect(apply).toBeEnabled();
  const refusals: { headers: Record<string, string>; detail: string }[] = [
    { headers: { Origin: ORIGIN }, detail: "CSRF token missing or wrong" },
    { headers: { Origin: "https://foreign.invalid", "X-CSRF-Token": csrf }, detail: "origin not allowed" },
  ];
  for (const { headers, detail } of refusals) {
    const refused = await page.request.post(APPLY, {
      data: { head: pending, applied },
      headers: { ...headers, "Idempotency-Key": "browser-refused" },
    });
    expect(refused.status()).toBe(403);
    expect(await refused.json()).toEqual({ detail });
    expect(await jobs()).toEqual(initialJobs);
  }

  const other = await context.newPage();
  await other.goto("/#/config");
  const otherEditor = other.getByLabel("Configuration (YAML)");
  await expect(otherEditor).toHaveValue(/allow_restart: false/);
  const newerYaml = (await otherEditor.inputValue()).trimEnd() + "\nmaintenance:\n  weekly_window: Mon 04:00 UTC\n";
  const draft = "# Unsaved while reviewing apply\n" + await editor.inputValue();
  const note = page.getByRole("textbox", { name: "Change note", exact: true });
  await editor.fill(draft);
  await note.fill("Keep this note");
  let captureRoute!: (route: Route) => void;
  const intercepted = new Promise<Route>(resolve => { captureRoute = resolve; });
  await page.route(`**${APPLY}`, captureRoute, { times: 1 });
  const isApply = (response: { url(): string }) => new URL(response.url()).pathname === APPLY;
  const staleResponse = page.waitForResponse(isApply);
  await apply.click();
  const held = await intercepted;
  let newer: string;
  try {
    expect(held.request().postDataJSON()).toEqual({ head: pending, applied });
    newer = await saveRevision(other, newerYaml);
  } finally {
    await held.continue();
    await other.close();
  }
  const stale = await staleResponse;
  expect(stale.status()).toBe(409);
  expect(await stale.json()).toMatchObject({ detail: { head: newer, applied } });
  await expect(page.getByRole("alert")).toContainText("Conflict");
  await expectRevisions(page, newer, applied);
  await expect(plan).toContainText(newer);
  await expect(editor).toHaveValue(draft);
  await expect(note).toHaveValue("Keep this note");
  await expect(page.getByRole("button", { name: "Load latest YAML" })).toBeVisible();
  expect(await jobs()).toEqual(initialJobs);

  const submitted = page.waitForResponse(isApply);
  await apply.click();
  const accepted = await submitted;
  expect(accepted.status()).toBe(202);
  expect(accepted.request().postDataJSON()).toEqual({ head: newer, applied });
  const job = await accepted.json();
  expect(job.state).toBe("queued");
  const expectOutcome = async (state: string) => {
    await expect(outcome.getByText(state, { exact: true })).toBeVisible();
    await expect(outcome).toContainText(newer);
  };
  await expectOutcome("queued");
  await expectRevisions(page, newer, applied);
  await expect(apply).toBeDisabled();
  const control = async (command: "claim-apply" | "release-apply") => {
    const response = await page.request.post(`/__browser_fixture__/${command}`, {
      headers: { Origin: ORIGIN, "X-Browser-Fixture-Token": TOKEN },
    });
    expect(response.status()).toBe(200);
  };
  await control("claim-apply");
  await expectOutcome("running");
  await expectRevisions(page, newer, applied);
  await expect(apply).toBeDisabled();
  await expect(editor).toHaveValue(draft);
  await control("release-apply");
  await expectOutcome("succeeded");
  await expectRevisions(page, newer, newer);
  await expect(editor).toHaveValue(draft);
  await expect(note).toHaveValue("Keep this note");
  expect(await jobs()).toEqual([
    expect.objectContaining({
      id: job.id,
      kind: "config_apply",
      state: "succeeded",
      payload: expect.objectContaining({ head: newer, applied }),
      result: expect.objectContaining({ config_revision: newer, previous_revision: applied }),
    }),
    ...initialJobs,
  ]);
  const readback = await page.request.get("/api/config");
  expect(readback.status()).toBe(200);
  expect(await readback.json()).toMatchObject({ head: newer, applied: newer, pending: false });
  await page.getByRole("button", { name: "Load latest YAML" }).click();
  await expect(editor).toHaveValue(/weekly_window: Mon 04:00 UTC/);
  await expect(note).toHaveValue("Keep this note");

  await page.reload();
  await expectOutcome("succeeded");
  await expectRevisions(page, newer, newer);
  await expect(plan).toHaveCount(0);
});
