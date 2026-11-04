import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { FlatCompat } from "@eslint/eslintrc";
import tseslint from "typescript-eslint";

const compat = new FlatCompat({ baseDirectory: dirname(fileURLToPath(import.meta.url)) });

export default tseslint.config(
  {
    ignores: [
      ".next/**",
      ".next-e2e/**",
      "node_modules/**",
      "coverage/**",
      "playwright-report/**",
      "test-results/**",
      ".lighthouseci/**",
      "next-env.d.ts",
      "lib/api-schema.d.ts",
    ],
  },
  ...compat.extends("next/core-web-vitals"),
  ...tseslint.configs.strict,
  {
    rules: {
      "no-console": ["error", { allow: ["warn", "error"] }],
      "@typescript-eslint/consistent-type-imports": "error",
      "@typescript-eslint/no-unused-vars": ["error", { argsIgnorePattern: "^_", varsIgnorePattern: "^_" }],
      "jsx-a11y/no-autofocus": "off",
    },
  },
  {
    files: ["e2e/**", "scripts/**", "**/*.test.ts", "**/*.test.tsx"],
    rules: { "no-console": "off" },
  },
  {
    // LHCI loads puppeteer scripts with require(); they must stay CommonJS.
    files: ["**/*.cjs"],
    languageOptions: {
      sourceType: "commonjs",
      globals: { require: "readonly", module: "writable", process: "readonly" },
    },
    rules: { "@typescript-eslint/no-require-imports": "off" },
  },
);
