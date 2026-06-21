import { defineConfig } from "@playwright/test";

// Serves the real static build at the GitHub Pages base path.
export default defineConfig({
  testDir: "tests/e2e",
  timeout: 60_000,
  use: { baseURL: "http://localhost:4321" },
  webServer: {
    command: "npm run build && npm run preview",
    url: "http://localhost:4321/encryptme/",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
  },
});
