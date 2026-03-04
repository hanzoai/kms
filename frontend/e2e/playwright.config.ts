import { defineConfig } from "@playwright/test";

export default defineConfig({
  timeout: 60000,
  expect: { timeout: 10000 },
  use: {
    baseURL: process.env.BASE_URL || "http://localhost:8080",
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    headless: true,
  },
  projects: [
    {
      name: "chromium",
      testDir: "./specs",
      use: { browserName: "chromium" },
    },
  ],
  webServer: process.env.CI
    ? undefined
    : {
        command: "cd .. && npm run dev",
        url: "http://localhost:8080",
        reuseExistingServer: true,
        timeout: 30000,
      },
});
