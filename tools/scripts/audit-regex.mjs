#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import safe from "safe-regex";
import ts from "typescript";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SKIP_DIRS = new Set(["node_modules", "dist", ".astro", "target"]);
const EXTS = new Set([".ts", ".tsx", ".js", ".mjs"]);

/** Every JavaScript and TypeScript file git tracks under root, sorted. Leftover folders
 *  a clean checkout doesn't have never count. */
export function trackedSources(root) {
  // A hook's GIT_DIR would point git at another repository.
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !name.startsWith("GIT_")),
  );
  return execFileSync("git", ["-C", root, "ls-files", "-z"], {
    encoding: "utf8",
    env,
    maxBuffer: 64 * 1024 * 1024,
  })
    .split("\0")
    .filter(
      (file) =>
        EXTS.has(path.extname(file)) &&
        !file.split("/").some((part) => SKIP_DIRS.has(part)) &&
        // Vendored libraries and the sample bundles the engine's tests scan aren't our code.
        !file.endsWith(".min.js") &&
        !file.split("/").includes("fixtures") &&
        existsSync(path.join(root, file)),
    )
    .sort();
}

const ALLOWED_SAFE_REGEX_FALSE_POSITIVES = new Map([
  [
    String.raw`^(?<name>.+?)\s+(?<from>\S+)\s+->\s+(?<to>\S+)(?:\s+•.*)?$`,
    "Bounded to one update-event title line; not applied to untrusted large blobs.",
  ],
  [String.raw`(\d+)(?:\.(\d+))?(?:\.(\d+))?`, "Simple version parser used on short event labels."],
  [String.raw`\b(?:localhost|127\.0\.0\.1)(?::\d+)?\b`, "Linear localhost redaction pattern."],
  [String.raw`^[a-z0-9]+(?:-[a-z0-9]+)*$`, "Linear kebab-case filename validator."],
  [
    String.raw`\bbackdrop-blur(?:-[a-z]+)?\b`,
    "Bounded class-token scan over authored HTML/CSS snippets.",
  ],
  [
    String.raw`(?:\p{Extended_Pictographic}|\p{Emoji_Presentation})`,
    "Unicode property scan for emoji usage over fetched page text.",
  ],
  [
    String.raw`[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}]\u{FE0F}?`,
    "Emoji detector over capped page text.",
  ],
  [
    String.raw`<h1[^>]*>[\s\S]*?<\/h1>[\s\S]*?<h[23][^>]*>[\s\S]*?<\/h[23]>`,
    "Small heading-order heuristic over capped page HTML.",
  ],
  [
    String.raw`[\u{1F300}-\u{1F9FF}\u{2600}-\u{26FF}].*?<h[23]`,
    "Small emoji-before-heading heuristic over capped page HTML.",
  ],
  [
    String.raw`<script\b[^>]*>([\s\S]*?)<\/script>`,
    "Script-content extraction over the scanner's bounded response body.",
  ],
  [
    String.raw`<script(?:\s[^>]*)?>(.+?)<\/script>`,
    "Script-content extraction over the scanner's bounded response body.",
  ],
  [String.raw`^(?:(?:\d{1,3})\.){3}\d{1,3}$`, "IPv4 literal recognizer over hostname-sized input."],
  [
    String.raw`^\s*#\[tauri::command(?:\([^)]*\))?\]\s*$`,
    "tauri-command-surface annotation detector over single source-file lines.",
  ],
  [
    String.raw`^\s*(?:pub(?:\s*\([^)]+\))?\s+)?(?:async\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)`,
    "tauri-command-surface Rust fn-signature parser over single source-file lines.",
  ],
  [
    String.raw`(?:[a-z_][a-z0-9_]*::)+([a-z_][a-z0-9_]*)`,
    "tauri-command-surface Rust module-path extractor over the bounded invoke_handler block.",
  ],
  [
    "\\binvoke(?:<[^>]*>)?\\s*\\(\\s*[\"'`]([a-z_][a-z0-9_]*)[\"'`]",
    "tauri-command-surface frontend invoke() call detector over source-file content.",
  ],
  [
    String.raw`^(\s*)(?:pub(?:\s*\([^)]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:extern\s+"[^"]+"\s+)?fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*[<(]`,
    "rust-function-lengths Rust fn-signature parser over single source-file lines.",
  ],
  [
    String.raw`(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$`,
    "IPv4 literal recognizer over URL-host-sized input.",
  ],
  [String.raw`^(\d+)\.(\d+)\.(\d+)$`, "Semver matcher over release version strings."],
  [String.raw`^v\d+\.\d+\.\d+(?:-[\w.-]+)?$`, "Semver tag matcher over release tag strings."],
  [String.raw`^\d+\.\d+\.\d+(?:-[\w.-]+)?$`, "Semver matcher over release version strings."],
  [
    String.raw`(?:export\s+)?const\s+([A-Z][A-Z0-9_]*(?:_LIMIT|_BUDGET|_CAP|_MAX_[A-Z_]+|_MAXLINES))\s*=\s*(\d+)`,
    "check-budget-ratchet *_LIMIT constant detector over single source-file lines.",
  ],
  [
    String.raw`\b(?:export\s+)?const\s+CATEGORY_LABELS\b`,
    "guardrail-category-rules CATEGORY_LABELS declaration detector over source lines.",
  ],
  [
    String.raw`const\s+\w*(CATEGORY_ORDER|FILTER_ORDER)\w*\s*(?::[^=]+)?=\s*\[[\s\S]{0,220}security[\s\S]{0,220}performance[\s\S]{0,220}seo[\s\S]{0,220}accessibility`,
    "guardrail-category-rules category-order detector; each [\\s\\S] segment is hard-capped at 220 chars over source files.",
  ],
  [
    String.raw`\b(?:export\s+)?const\s+DOMAIN_STYLES\b`,
    "guardrail-category-rules DOMAIN_STYLES declaration detector over source lines.",
  ],
  [
    String.raw`^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)`,
    "guardrail-rust-display-log-rules fn-name extractor over single trimmed source lines.",
  ],
  [
    String.raw`impl(?:<[^>]*>)?\s+(?:std::)?fmt::(Display|Debug)\s+for\s+([\w:]+)`,
    "guardrail-rust-display-log-rules Display/Debug impl detector over repo Rust source files.",
  ],
  [
    String.raw`\bfn\s+(\w+)\s*\([^)]*\)\s*(?:->\s*[^{;]+?)?\{`,
    "guardrail-empty-test-body-rules Rust fn-signature detector over single source lines.",
  ],
  [
    String.raw`\bsafeListen\s*(<[^>]*>)?\s*\(`,
    "guardrail-event-fabric-rules safeListen() call detector over source lines.",
  ],
  [
    String.raw`\bcommand\s*(?:<[^(;]*?>)?\s*\(\s*"([a-z0-9_]+)"`,
    "guardrail-invoke-acl-rules command() name detector over source lines.",
  ],
  [
    String.raw`\b(?:FROM|JOIN|INSERT INTO|UPDATE)\s+(\w+)(?:\s+(?!ON\b|WHERE\b|SET\b|JOIN\b|LEFT\b|ORDER\b|GROUP\b|VALUES\b|AS\b)(\w+))?`,
    "guardrail-mcp-schema-rules SQL table/alias detector over bounded query strings.",
  ],
  [
    String.raw`^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`,
    "release.mjs semver validator over a single CLI version argument.",
  ],
  [
    String.raw`^rounded(-.+)?$`,
    "guardrail-tailwind-removal utility-shape matcher over single class tokens.",
  ],
  [
    String.raw`^([a-z0-9-]+:)+`,
    "guardrail-tailwind-removal variant-prefix stripper over single class tokens; the ':' delimiter makes each repetition unambiguous (linear).",
  ],
]);

function scriptKindFor(file) {
  if (file.endsWith(".tsx")) return ts.ScriptKind.TSX;
  if (file.endsWith(".ts")) return ts.ScriptKind.TS;
  if (file.endsWith(".mjs")) return ts.ScriptKind.JS;
  return ts.ScriptKind.JS;
}

function parseRegexLiteral(text) {
  const finalSlash = text.lastIndexOf("/");
  if (!text.startsWith("/") || finalSlash <= 0) return null;
  return text.slice(1, finalSlash);
}

function staticRegExpPattern(node) {
  if (!ts.isCallExpression(node) && !ts.isNewExpression(node)) return null;
  if (!ts.isIdentifier(node.expression) || node.expression.text !== "RegExp") return null;
  const [firstArg] = node.arguments ?? [];
  if (!firstArg) return null;
  if (ts.isStringLiteral(firstArg) || ts.isNoSubstitutionTemplateLiteral(firstArg)) {
    return firstArg.text;
  }
  return null;
}

function lineFor(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
}

function main() {
  const files = trackedSources(ROOT);
  if (!files.some((file) => file.startsWith("tools/scripts/"))) {
    console.error("audit-regex: found no tracked sources under tools/scripts");
    process.exit(2);
  }
  const findings = [];

  for (const file of files) {
    const source = readFileSync(path.join(ROOT, file), "utf8");
    const sourceFile = ts.createSourceFile(
      file,
      source,
      ts.ScriptTarget.Latest,
      true,
      scriptKindFor(file),
    );

    function visit(node) {
      const pattern =
        node.kind === ts.SyntaxKind.RegularExpressionLiteral
          ? parseRegexLiteral(node.getText(sourceFile))
          : staticRegExpPattern(node);

      if (
        pattern &&
        !ALLOWED_SAFE_REGEX_FALSE_POSITIVES.has(pattern) &&
        !safe(pattern, { limit: 50 })
      ) {
        findings.push({
          file,
          line: lineFor(sourceFile, node),
          pattern,
          form: node.kind === ts.SyntaxKind.RegularExpressionLiteral ? "literal" : "RegExp",
        });
      }

      ts.forEachChild(node, visit);
    }

    visit(sourceFile);
  }

  if (findings.length === 0) {
    console.log(`safe-regex: no catastrophic patterns found in ${files.length} tracked files`);
    process.exit(0);
  }

  console.log(`safe-regex flagged ${findings.length} pattern(s):\n`);
  for (const finding of findings) {
    console.log(`  ${finding.file}:${finding.line} (${finding.form})`);
    console.log(`    /${finding.pattern}/`);
  }
  process.exit(1);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href)
  main();
