// @ts-check
import { defineConfig } from "astro/config";
import tailwindcss from "@tailwindcss/vite";
import { fileURLToPath } from "node:url";

// libsodium-wrappers-sumo's ESM build has a broken relative import; alias to the
// intact CJS build (vite handles the CJS->ESM interop for the browser bundle).
const sodiumCjs = fileURLToPath(
  new URL(
    "./node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js",
    import.meta.url
  )
);

// GitHub Pages project page. Override via env if the repo/owner differs.
const site = process.env.SITE_URL ?? "https://sshlainatwired.github.io";
const base = process.env.BASE_PATH ?? "/encryptme/";

// https://astro.build/config
export default defineConfig({
  site,
  base,
  output: "static",
  vite: {
    plugins: [tailwindcss()],
    resolve: {
      alias: { "libsodium-wrappers-sumo": sodiumCjs },
    },
  },
});
