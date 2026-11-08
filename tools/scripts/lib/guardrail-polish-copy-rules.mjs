const POLISH_RUST_FILES = [
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/page_leftovers.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/ai_aesthetic.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/copy_content.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/css_architecture.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/framework_defaults.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/html_quality.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/meta_infra.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/titles.rs",
  // Guidance and confidence reasons reach hosted results with every fired signal.
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/guidance.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/check_result.rs",
  "apps/desktop/src-tauri/crates/engine/src/checks/polish/css_grade.rs",
];

// The bundled fix-guide lead sentences shown before the Rust finding copy;
// same judgmental-language ban applies since a lead is also user-visible.
const POLISH_LEAD_FILE = "apps/desktop/src/lib/fix-guides/polish.ts";
// Matches a `lead:` property regardless of quote style (double, single, or
// template literal) so a lead is never silently skipped just because it was
// written with a different quote character than the rest of the file.
const LEAD_LINE_RE = /^\s*lead:\s*['"`]/;

// Regression net for the exact overclaim phrasings a maintainer review
// found across two fix rounds (a lead asserting more than the check itself
// establishes: production exposure from a localhost-only signal, an
// absolute inability claim from a bounded static check, a definite visible
// failure from an inconclusive probe, and so on). This list is not a
// semantic overclaim detector - a new lead can still overclaim in words not
// listed here - so it only catches a repeat of a previously reviewed
// mistake. The maintainer's read of new leads stays the real gate.
const OVERCLAIM_PATTERNS = [
  {
    re: /\banyone (?:can )?reconstruct\b/i,
    reason:
      "overclaim - a referenced source map is not proven publicly fetchable; say the scan saw only the reference",
  },
  {
    re: /\bwill fail\b/i,
    reason:
      "overclaim - a localhost-only signal does not establish deployed behavior; say what the local preview shows",
  },
  {
    re: /\bhas no way\b/i,
    reason:
      "overclaim - a bounded static check cannot prove an absolute inability; say what the scan did not find",
  },
  {
    re: /\bshows a broken\b/i,
    reason:
      "overclaim - an inconclusive probe is not a confirmed visible failure; say the probe failed or was inconclusive",
  },
  {
    re: /\bblocks crawling across\b/i,
    reason:
      "overclaim - a wildcard robots rule can be overridden by a more specific group; keep 'by default'",
  },
  {
    re: /\bstill carries\b/i,
    reason:
      "overclaim - the check also fires on missing, empty, and placeholder titles, not only a leftover default",
  },
  {
    // Narrowed from a bare /blurred/ ban: glassmorphism's own Rust guidance
    // genuinely describes "translucent, blurred surfaces," so a blanket
    // ban on the word flagged that legitimate, previously reviewed lead.
    // The floating-blobs overclaim this round found was specifically
    // "blurred shapes"; scope the pattern to that phrase.
    re: /\bblurred shapes\b/i,
    reason: "overclaim - some signals in this family fire without blur evidence; do not claim blur",
  },
  {
    re: /\bmaking .* confusing\b/i,
    reason: "overclaim - the check flags the pattern for review, not a confirmed usability defect",
  },
  {
    re: /\bwithout (?:actually )?saying anything\b/i,
    reason: "overclaim - a buzzword-density match is not proof the copy is meaningless",
  },
  {
    re: /\bbuilt almost entirely\b/i,
    reason:
      "overclaim - a low semantic-element ratio does not prove the page is nearly all generic containers",
  },
];

// Case-insensitive bans applied only to user-visible string lines.
const BANNED_PATTERNS = [
  { re: /\boverused\b/i, reason: "judgmental - say 'heavy usage' or '<count> detected'" },
  { re: /\bcookie-?cutter\b/i, reason: "judgmental - say 'default scaffold markers'" },
  {
    re: /generic\s+ai-written/i,
    reason: "accusatory - say 'high marketing buzzword density'",
  },
  {
    re: /\bstill on\b/i,
    reason: "judgmental - say 'hosting on <subdomain>' factually",
  },
  {
    re: /\bvibe code\b/i,
    reason: "internal jargon; not for user-visible strings",
  },
  {
    re: /\bvibed\b/i,
    reason: "internal jargon; not for user-visible strings",
  },
  {
    re: /\bChatGPT\b/i,
    reason: "naming a competitor's product in scanner output is unshippable",
  },
  {
    re: /\bsmells like a prompt\b/i,
    reason: "accusatory verdict label",
  },
  {
    re: /\byou both know it\b/i,
    reason: "accusatory second-person phrasing",
  },
  {
    re: /\bhandcrafted\b/i,
    reason: "implies intent the scanner cannot verify",
  },
  {
    re: /AI fingerprint/i,
    reason: "implies intent the scanner cannot verify",
  },
  {
    re: /\bsuspicious\b/i,
    reason: "accusatory - describe the signal count, not a verdict",
  },
];

// Test modules contain the banned phrases as detection needles.
function userVisibleStringLines(content) {
  const lines = content.split("\n");
  const out = [];
  let inTestModule = false;
  let testBraceDepth = 0;
  let pendingTestModule = false;
  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];
    const trimmed = line.trimStart();
    if (/#\[cfg\(test\)\]/.test(line)) {
      pendingTestModule = true;
    } else if (pendingTestModule && /\bmod\s+\w+\s*\{/.test(line)) {
      inTestModule = true;
      testBraceDepth = 1;
      pendingTestModule = false;
      continue;
    }
    if (inTestModule) {
      for (const ch of line) {
        if (ch === "{") testBraceDepth += 1;
        else if (ch === "}") testBraceDepth -= 1;
      }
      if (testBraceDepth <= 0) {
        inTestModule = false;
        testBraceDepth = 0;
      }
      continue;
    }
    if (trimmed.startsWith("//")) continue;
    if (!/"[^"\n]*"/.test(line)) continue;
    out.push({ line, index: i + 1 });
  }
  return out;
}

// One runner entry covers both user-facing copy checks.
import { accessibilityNamingFailures } from "./guardrail-accessibility-naming-rules.mjs";

export function polishCopySafetyFailures(read, exists, listFiles) {
  const failures = [...accessibilityNamingFailures(read, exists, listFiles)];
  for (const relativePath of POLISH_RUST_FILES) {
    if (!exists(relativePath)) {
      failures.push(
        `${relativePath} is missing - polish copy guardrail expects all polish source files to exist.`,
      );
      continue;
    }
    const content = read(relativePath);
    const lines = userVisibleStringLines(content);
    for (const { line, index } of lines) {
      for (const { re, reason } of BANNED_PATTERNS) {
        if (re.test(line)) {
          failures.push(
            `${relativePath}:${index} - banned polish copy: ${re}. ${reason}. Line: ${line.trim()}`,
          );
        }
      }
    }
  }

  if (!exists(POLISH_LEAD_FILE)) {
    failures.push(
      `${POLISH_LEAD_FILE} is missing - polish copy guardrail expects the bundled polish lead sentences to exist.`,
    );
  } else {
    const leadLines = read(POLISH_LEAD_FILE).split("\n");
    for (let i = 0; i < leadLines.length; i += 1) {
      const line = leadLines[i];
      if (!/^\s*lead:\s*/.test(line)) continue;
      if (!LEAD_LINE_RE.test(line)) {
        failures.push(
          `${POLISH_LEAD_FILE}:${i + 1} - a lead line does not use a recognized quote style (double, single, or template literal); the copy guardrail cannot scan it. Line: ${line.trim()}`,
        );
        continue;
      }
      for (const { re, reason } of [...BANNED_PATTERNS, ...OVERCLAIM_PATTERNS]) {
        if (re.test(line)) {
          failures.push(
            `${POLISH_LEAD_FILE}:${i + 1} - banned polish copy: ${re}. ${reason}. Line: ${line.trim()}`,
          );
        }
      }
    }
  }

  return failures;
}
