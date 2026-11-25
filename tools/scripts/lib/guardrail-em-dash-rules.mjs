import { lazyPluralFailures } from "./guardrail-issue-copy-rules.mjs";

const EM_DASH = "\u2014";
const ALLOW_MARKER = "allow-em-dash";

// Top-level + standalone guides not caught by the AGENTS/CLAUDE/README sweep.
const EXPLICIT_GUIDES = ["README.md", "CONTRIBUTING.md", "AGENTS.md", "CLAUDE.md"];

export function emDashFailures(read, exists, listFiles, scriptDirectories = ["tools/scripts"]) {
  const failures = lazyPluralFailures(read, exists, listFiles);
  const scanned = new Set(EXPLICIT_GUIDES);
  // All tracked docs are maintained public documentation.
  for (const file of listFiles("docs", (f) => f.endsWith(".md"))) {
    scanned.add(file);
  }
  // Per-app guides anywhere under apps/ (listFiles skips node_modules/dist/target).
  for (const file of listFiles("apps", (f) => /(?:^|\/)(?:AGENTS|CLAUDE|README)\.md$/i.test(f))) {
    scanned.add(file);
  }
  // Maintained tooling scripts (guardrail rules, ratchets, dev helpers).
  for (const file of scriptDirectories.flatMap((dir) =>
    listFiles(dir, (f) => /\.(?:mjs|cjs|js|sh)$/.test(f)),
  )) {
    scanned.add(file);
  }
  // Rust scanner source contains user-facing issue copy.
  for (const dir of ["apps/desktop/src-tauri/src", "apps/desktop/src-tauri/crates"]) {
    if (!exists(dir)) continue;
    for (const file of listFiles(dir, (f) => f.endsWith(".rs"))) {
      scanned.add(file);
    }
  }
  // Keep checking TypeScript and CSS used in scanner fixtures.
  if (exists("apps/desktop/src-tauri")) {
    for (const file of listFiles("apps/desktop/src-tauri", (f) => /\.(?:ts|tsx|css)$/.test(f))) {
      scanned.add(file);
    }
  }
  // Hooks config lives at the repo root next to the ratchet it drives.
  scanned.add("lefthook.yml");

  for (const file of scanned) {
    if (!exists(file)) continue;
    const lines = read(file).split("\n");
    for (let i = 0; i < lines.length; i += 1) {
      if (lines[i].includes(EM_DASH) && !lines[i].includes(ALLOW_MARKER)) {
        failures.push(
          `${file}:${i + 1} - uses an em-dash (U+2014); use a hyphen "-" instead. Line: ${lines[i].trim()}`,
        );
      }
    }
  }
  return failures;
}
