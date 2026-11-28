import { defineConfig, devices } from "@playwright/test";

const port = 8091;

export default defineConfig({
  testDir: "e2e",
  timeout: 45_000,
  retries: process.env.CI ? 1 : 0,
  use: { baseURL: `http://127.0.0.1:${port}`, locale: "de-DE", trace: "off" },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 900 } }, testIgnore: /mobile\.spec\.ts/ },
    { name: "phone", use: { ...devices["Pixel 7"] }, testMatch: /mobile\.spec\.ts/ },
  ],
  webServer: {
    command: `uv run opstend demo --listen 127.0.0.1:${port} --demo-delay 0.05`,
    cwd: "..",
    url: `http://127.0.0.1:${port}/api/session`,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
