import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: ".",
  testMatch: "cloudscape.spec.mjs",
  fullyParallel: true,
  forbidOnly: true,
  retries: 0,
  timeout: 30_000,
  use: {
    baseURL: "http://heteronetwork.test",
    locale: "ja-JP",
    timezoneId: "Asia/Tokyo",
    trace: "retain-on-failure",
  },
  reporter: [["list"]],
});
