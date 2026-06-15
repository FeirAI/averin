import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Client-only SPA (not SvelteKit). The dev server proxies /v2 to the feir server.
export default defineConfig({
  plugins: [svelte()],
  server: {
    proxy: {
      "/v2": "http://localhost:8080",
    },
  },
  build: { outDir: "dist", emptyOutDir: true },
});
