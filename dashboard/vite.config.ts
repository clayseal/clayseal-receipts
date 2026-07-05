import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      "/agent-run-api": {
        target: "http://127.0.0.1:8790",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/agent-run-api/, ""),
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    coverage: {
      provider: "v8",
      // Emit a text summary for the CI log, plus machine-readable reports so
      // the workflow can surface blind spots and upload an HTML artifact.
      reporter: ["text", "text-summary", "json-summary", "html", "lcov"],
      reportsDirectory: "./coverage",
      include: ["src/**/*.{ts,tsx}"],
      exclude: [
        "src/**/*.d.ts",
        "src/test/**",
        "src/**/*.test.{ts,tsx}",
        "src/main.tsx",
      ],
    },
  },
});
