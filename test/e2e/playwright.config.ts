import { defineConfig } from "@playwright/test";

const port = process.env.LABLDAP_E2E_PORT ?? "4173";
const baseURL = process.env.LABLDAP_E2E_BASE_URL ?? `http://127.0.0.1:${port}`;
const useMock = process.env.LABLDAP_E2E_BASE_URL === undefined;

export default defineConfig({
  testDir: "./specs",
  globalTeardown: "./global-teardown.ts",
  fullyParallel: false,
  workers: 1,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [["list"], ["html", { open: "never", outputFolder: "playwright-report" }]],
  outputDir: "test-results",
  use: {
    baseURL,
    screenshot: "only-on-failure",
    // Action log is retained for failures; page snapshots/screenshots inside
    // the zip are off so filled password fields are not stored as pixels.
    // fill() values and POST bodies still land in trace JSON and are scrubbed
    // from the zip by helpers/redact.mjs in global teardown.
    trace: { mode: "retain-on-failure", snapshots: false, screenshots: false, sources: false },
    video: "off",
    extraHTTPHeaders: { "X-Request-ID": "e2e" },
  },
  webServer: useMock
    ? {
        command: "node ./mock-server.mjs",
        url: `${baseURL}/health`,
        reuseExistingServer: false,
        timeout: 30_000,
        env: {
          ...process.env,
          LABLDAP_E2E_PORT: port,
        },
      }
    : undefined,
});
