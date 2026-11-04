import react from "@vitejs/plugin-react";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": fileURLToPath(new URL("./", import.meta.url)) } },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./test/setup.ts"],
    include: ["**/*.test.{ts,tsx}"],
    exclude: ["node_modules/**", ".next/**", "e2e/**"],
    coverage: {
      provider: "v8",
      include: ["lib/**/*.ts", "hooks/**/*.ts"],
      exclude: ["lib/**/*.test.ts", "hooks/**/*.test.ts", "lib/api-schema.d.ts", "lib/types.ts"],
      reporter: ["text", "text-summary", "html"],
      thresholds: { lines: 90, statements: 90, functions: 85, branches: 80 },
    },
  },
});
