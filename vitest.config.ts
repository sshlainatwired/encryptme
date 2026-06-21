import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// The libsodium-wrappers-sumo ESM build ships a broken relative import; its CJS
// build is intact. Alias to CJS everywhere so node + browser bundling both work.
const sodiumCjs = fileURLToPath(
  new URL(
    "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js",
    import.meta.url
  )
);

export default defineConfig({
  resolve: {
    alias: { "libsodium-wrappers-sumo": sodiumCjs },
  },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
  },
});
