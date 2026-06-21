import { test, expect } from "@playwright/test";
import { readFileSync } from "node:fs";

// Exercises the real UI through the in-memory fallback path (FSA disabled), and
// asserts nothing is ever sent off-host.
test("encrypt then decrypt round-trips a file via the UI", async ({ page }) => {
  const offsite: string[] = [];
  page.on("request", (r) => {
    const u = r.url();
    if (u.startsWith("http") && !u.includes("localhost") && !u.includes("127.0.0.1")) {
      offsite.push(u);
    }
  });

  // Force the Blob fallback so we can capture downloads (no native save dialog).
  await page.addInitScript(() => {
    Object.defineProperty(window, "showSaveFilePicker", { value: undefined });
  });

  await page.goto("/encryptme/");

  const original = Buffer.from("the quick brown fox — encrypt me!\n".repeat(5000), "utf8");
  const password = "correct horse battery staple";

  // Encrypt
  await page.locator('[data-input="encrypt"]').setInputFiles({
    name: "message.txt",
    mimeType: "text/plain",
    buffer: original,
  });
  await page.locator('[data-el="enc-pw"]').fill(password);
  await page.locator('[data-el="enc-pw2"]').fill(password);
  const [encDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.locator('[data-act="encrypt"]').click(),
  ]);
  expect(encDownload.suggestedFilename()).toBe("message.txt.enc");
  const encPath = await encDownload.path();
  const encBytes = readFileSync(encPath);
  expect(encBytes.length).toBeGreaterThan(original.length); // header + tags

  await expect(page.locator('[data-el="result"]')).toContainText(/done/i);

  // Decrypt
  await page.locator('[data-tab="decrypt"]').click();
  await page.locator('[data-input="decrypt"]').setInputFiles({
    name: "message.txt.enc",
    mimeType: "application/octet-stream",
    buffer: encBytes,
  });
  await expect(page.locator('[data-el="dec-detected"]')).toContainText(/password/i);
  await page.locator('[data-el="dec-pw"]').fill(password);
  const [decDownload] = await Promise.all([
    page.waitForEvent("download"),
    page.locator('[data-act="decrypt"]').click(),
  ]);
  expect(decDownload.suggestedFilename()).toBe("message.txt");
  const decBytes = readFileSync(await decDownload.path());

  expect(Buffer.compare(decBytes, original)).toBe(0);
  expect(offsite, `unexpected off-host requests: ${offsite.join(", ")}`).toEqual([]);
});
