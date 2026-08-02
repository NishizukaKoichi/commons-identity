import { defineConfig } from "vitest/config";

export default defineConfig({
  base: process.env.BASE_PATH ?? "/",
  clearScreen: false,
  envPrefix: ["VITE_", "TAURI_"],
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["src/**/*.test.ts"],
    restoreMocks: true,
  },
});
