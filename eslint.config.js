import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";
import prettierConfig from "eslint-config-prettier/flat";
import { defineConfig, globalIgnores } from "eslint/config";
import { globSync } from "node:fs";

const extensions = await Promise.all(
  globSync("tools/*/tooling.config.mjs", { cwd: new URL(".", import.meta.url) }).map(
    (file) => import(new URL(file, import.meta.url)),
  ),
);

export default defineConfig([
  globalIgnores([
    "**/.astro",
    "**/.wrangler",
    "**/dist",
    // Ignore leftover output from the removed MCP server.
    "apps/mcp-server/**",
    "**/*.d.ts",
    "**/node_modules",
    "**/target",
    "apps/desktop/src-tauri/target",
    "apps/desktop/src-tauri/gen",
    // Generated design-system bundle (already gitignored).
    "ds-bundle/**",
    // Local scratch and captured-run output.
    "output/**",
  ]),
  {
    files: [
      "eslint.config.js",
      "tools/scripts/**/*.mjs",
      ...extensions.flatMap((x) => x.eslintFiles),
    ],
    extends: [
      js.configs.recommended,
      prettierConfig, // must come last: disables ESLint rules prettier formats
    ],
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: globals.node,
    },
    rules: {
      "no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrors: "all",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      tseslint.configs.recommended,
      prettierConfig, // must come last: disables ESLint rules prettier formats
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
          destructuredArrayIgnorePattern: "^_",
        },
      ],
    },
  },
]);
