import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import reactCompiler from "eslint-plugin-react-compiler";
import checkFile from "eslint-plugin-check-file";
import tseslint from "typescript-eslint";
import prettierConfig from "eslint-config-prettier/flat";
import { defineConfig, globalIgnores } from "eslint/config";

const LOWER_OR_KEBAB_CASE = "@(+([a-z0-9])|+([a-z])*([a-z0-9])*(-+([a-z0-9])))";
const SOURCE_COMPATIBLE_CASE =
  "@(use[A-Z]*|*([A-Z]*([a-z0-9]))|+([a-z0-9])|+([a-z])*([a-z0-9])*(-+([a-z0-9])))";
const TEST_SUFFIXES =
  "*.{test,spec,behavior,render,performance,capture,copilot,navigation,npm-audit}.{ts,tsx}";
const FILENAME_RULE_OPTIONS = { ignoreMiddleExtensions: true };
// A message argument shown to a person: JSX text, an object property, a
// template literal, or the message argument of a toast/error/warning call.
// `logger.*` and `console.*` are diagnostics, not people, and are excluded.
const RAW_ERROR_MESSAGE_CONTEXT =
  ':matches(JSXExpressionContainer, Property, TemplateLiteral, CallExpression[callee.type="MemberExpression"][callee.object.name!="logger"][callee.object.name!="console"][callee.property.name=/^(error|warning|info|success|toast)$/], CallExpression[callee.type="Identifier"][callee.name=/^(error|showError|toastError|set[A-Z]\\w*Error)$/])';
// A bare `String(e)`/`String(err)`/`String(error)` inside that context, either
// passed directly or nested one level inside a ternary or `||`/`??` fallback
// (`err instanceof Error ? err.message : String(err)` is the common shape).
const RAW_STRING_ERROR_SELECTOR = [
  `${RAW_ERROR_MESSAGE_CONTEXT} > CallExpression[callee.name="String"][arguments.0.type="Identifier"][arguments.0.name=/^(e|err|error)$/]`,
  `${RAW_ERROR_MESSAGE_CONTEXT} > :matches(ConditionalExpression, LogicalExpression) CallExpression[callee.name="String"][arguments.0.type="Identifier"][arguments.0.name=/^(e|err|error)$/]`,
].join(", ");

export default defineConfig([
  globalIgnores([
    "**/.astro",
    "**/.wrangler",
    "**/dist",
    "**/*.d.ts",
    "**/node_modules",
    "apps/desktop/src-tauri/target",
    "apps/desktop/src-tauri/gen",
    "apps/mcp-server/dist",
    "apps/mcp-server/dist-bundle",
    // Generated design-system bundle (already gitignored).
    "ds-bundle/**",
    // Local scratch and captured-run output.
    "output/**",
  ]),
  {
    files: ["eslint.config.js", "tools/scripts/**/*.mjs", "apps/mcp-server/test/**/*.mjs"],
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
      reactHooks.configs.flat.recommended,
      reactCompiler.configs.recommended,
      reactRefresh.configs.vite,
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
      // Allow re-exporting plain constants / CVA variant objects alongside
      // components. HMR only matters for component functions.
      "react-refresh/only-export-components": ["error", { allowConstantExport: true }],
      // Keep compiler-oriented hooks rules enforced.
      "react-hooks/preserve-manual-memoization": "error",
      "react-hooks/refs": "error",
      "react-hooks/immutability": "error",
      // Legitimate asynchronous state effects require justified inline disables.
      "react-hooks/set-state-in-effect": "error",
      // Missing hook dependencies fail instead of accumulating as warnings.
      "react-hooks/exhaustive-deps": "error",
    },
  },
  {
    files: ["apps/desktop/src/**/*.{ts,tsx}"],
    ignores: ["apps/desktop/src/**/*.d.ts"],
    plugins: {
      "check-file": checkFile,
    },
  },
  {
    files: ["apps/desktop/src/**/*.tsx"],
    ignores: [
      "apps/desktop/src/main.tsx",
      "apps/desktop/src/**/use*.tsx",
      `apps/desktop/src/**/${TEST_SUFFIXES}`,
      "apps/desktop/src/components/ui/**/*.{ts,tsx}",
    ],
    rules: {
      "check-file/filename-naming-convention": [
        "error",
        {
          "**/*.tsx": "PASCAL_CASE",
        },
        FILENAME_RULE_OPTIONS,
      ],
    },
  },
  {
    files: ["apps/desktop/src/**/*.ts"],
    ignores: [
      "apps/desktop/src/**/*.d.ts",
      // Bare `use*` also matches non-hook files like `user-facing-error.ts`,
      // so this exclusion targets the hook naming convention specifically.
      "apps/desktop/src/**/use[A-Z]*.ts",
      `apps/desktop/src/**/${TEST_SUFFIXES}`,
    ],
    rules: {
      "check-file/filename-naming-convention": [
        "error",
        {
          "**/*.ts": LOWER_OR_KEBAB_CASE,
        },
        FILENAME_RULE_OPTIONS,
      ],
    },
  },
  {
    files: ["apps/desktop/src/**/use[A-Z]*.{ts,tsx}"],
    ignores: [`apps/desktop/src/**/${TEST_SUFFIXES}`],
    rules: {
      "check-file/filename-naming-convention": [
        "error",
        {
          "**/use[A-Z]*.{ts,tsx}": "use[A-Z]*",
        },
        FILENAME_RULE_OPTIONS,
      ],
    },
  },
  {
    files: ["apps/desktop/src/components/ui/**/*.{ts,tsx}"],
    rules: {
      "check-file/filename-naming-convention": [
        "error",
        {
          "apps/desktop/src/components/ui/**/*.{ts,tsx}": SOURCE_COMPATIBLE_CASE,
        },
        FILENAME_RULE_OPTIONS,
      ],
    },
  },
  {
    files: [`apps/desktop/src/**/${TEST_SUFFIXES}`],
    rules: {
      "check-file/filename-naming-convention": [
        "error",
        {
          [`apps/desktop/src/**/${TEST_SUFFIXES}`]: SOURCE_COMPATIBLE_CASE,
        },
        FILENAME_RULE_OPTIONS,
      ],
    },
  },
  {
    // Interactive controls must use Button or a native button for keyboard
    // behavior, and people never see a raw String(error).
    files: ["apps/desktop/src/**/*.{ts,tsx}"],
    ignores: [`apps/desktop/src/**/${TEST_SUFFIXES}`],
    rules: {
      "no-restricted-syntax": [
        "error",
        {
          selector:
            'JSXOpeningElement[name.name="span"] > JSXAttribute[name.name="role"][value.value="button"]',
          message:
            'Use `<Button unstyled>` or a native <button> instead of `<span role="button">` - a span reimplements keyboard activation by hand and drops Space-key support (audit F32).',
        },
        {
          selector: RAW_STRING_ERROR_SELECTOR,
          message:
            "Do not show String(error) to people. Pass the rejection through userFacingError(error, fallback) from @/lib/user-facing-error so the message is a sentence with a next step.",
        },
      ],
    },
  },
  {
    // Provider and hook co-location intentionally accepts a full refresh on edit.
    files: ["**/hooks/use*.tsx"],
    rules: {
      "react-refresh/only-export-components": "off",
    },
  },
  {
    files: ["**/*.{test,spec,behavior,render}.{ts,tsx}", "**/__tests__/**/*.{ts,tsx}"],
    rules: {
      "@typescript-eslint/no-explicit-any": "off",
    },
  },
  {
    // Dialog and menu tests drive real keyboard and pointer sequences.
    files: [
      "apps/desktop/src/components/layout/PageGuide.test.tsx",
      "apps/desktop/src/components/layout/CommandPalette.test.tsx",
      "apps/desktop/src/components/layout/TopBar.test.tsx",
      "apps/desktop/src/components/privacy/TelemetryConsentPrompt.test.tsx",
      "apps/desktop/src/components/ui/dialog.test.tsx",
    ],
    rules: {
      "no-restricted-imports": [
        "error",
        {
          paths: [
            {
              name: "@testing-library/react",
              importNames: ["fireEvent"],
              message:
                "Use @testing-library/user-event here so Escape, Tab, and click sequences exercise real focus management.",
            },
          ],
        },
      ],
    },
  },
]);
