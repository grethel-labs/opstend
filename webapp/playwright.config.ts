import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  use: { baseURL: "http://localhost:19080", trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
  webServer: [
    {
      command: "../.venv/bin/python ../tests/integration/browser_server.py",
      url: "http://localhost:19080/healthz",
      reuseExistingServer: false,
      gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
      env: { PYTHONPATH: "../src" },
    },
    {
      command: "../.venv/bin/python ../tests/integration/browser_fleet_policy_server.py",
      url: "http://localhost:19081/healthz",
      reuseExistingServer: false,
      gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
      env: { PYTHONPATH: "../src" },
    },
    {
      command: "../.venv/bin/python ../tests/integration/browser_fleet_power_server.py",
      url: "http://localhost:19082/healthz",
      reuseExistingServer: false,
      gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
      env: { PYTHONPATH: "../src" },
    },
  ],
});
