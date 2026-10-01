/// <reference types="node" />

import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { CODE_FIX_GUIDE_IDS, getCodeFixGuide } from "./code-fix-guides";
import { FIX_GUIDE_ALIASES, FIX_GUIDE_IDS, LEGACY_FIX_GUIDE_IDS, getFixGuide } from "./fix-guides";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RUST_SRC = path.resolve(HERE, "../../src-tauri/src");
const ENGINE_CHECKS = path.resolve(HERE, "../../src-tauri/crates/engine/src/checks");

function walkRustFiles(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walkRustFiles(fullPath, files);
    } else if (entry.isFile() && fullPath.endsWith(".rs")) {
      files.push(fullPath);
    }
  }
  return files;
}

function walkGuidanceFiles(dir: string, files: string[] = []): string[] {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "tests") continue;
      walkGuidanceFiles(fullPath, files);
    } else if (entry.isFile() && (fullPath.endsWith(".ts") || fullPath.endsWith(".rs"))) {
      files.push(fullPath);
    }
  }
  return files;
}

function collectMatches(source: string, pattern: RegExp): string[] {
  return Array.from(source.matchAll(pattern), (match) => match[1]).filter(Boolean);
}

function isTestOnlyRustFile(file: string): boolean {
  return file.endsWith("_tests.rs");
}

function productionHalf(source: string): string {
  const withoutExternalTestModules = source.replace(
    /#\[cfg\(test\)\]\s*mod\s+[A-Za-z0-9_]+\s*;/g,
    "",
  );
  const inlineTestModule = withoutExternalTestModules.search(
    /#\[cfg\(test\)\]\s*mod\s+[A-Za-z0-9_]+\s*\{/,
  );
  return inlineTestModule >= 0
    ? withoutExternalTestModules.slice(0, inlineTestModule)
    : withoutExternalTestModules;
}

function collectWebIssueIds(): string[] {
  const ids = new Set<string>();
  for (const file of [
    ...walkRustFiles(path.join(RUST_SRC, "checks")),
    ...walkRustFiles(ENGINE_CHECKS),
  ]) {
    if (isTestOnlyRustFile(file)) continue;
    const source = productionHalf(readFileSync(file, "utf8"));
    collectMatches(source, /check_id:\s*"([^"]+)"/g).forEach((id) => ids.add(id));
    collectMatches(source, /fn\s+id\(&self\)\s*->\s*&str\s*\{\s*"([^"]+)"/g).forEach((id) =>
      ids.add(id),
    );
    collectMatches(source, /PolishResult::(?:fired|clear)\(\s*"([a-z0-9-]+)"/g).forEach((id) =>
      ids.add(`polish.${id}`),
    );
    Array.from(
      source.matchAll(/const\s+([A-Z_]*CHECK_IDS?[A-Z_]*):\s*&str\s*=\s*"([^"]+)"/g),
    ).forEach(([, name, id]) => {
      if (!name.endsWith("_PREFIX")) ids.add(id);
    });
  }

  ids.add("security.cookies");
  ids.add("security.exposed_files");
  ids.add("performance.tbt");
  ids.delete("security.headers");

  const webviewResults = productionHalf(
    readFileSync(path.join(RUST_SRC, "core/scanner/webview_results.rs"), "utf8"),
  );
  collectMatches(webviewResults, /cwv_metric_result\(\s*"([^"]+)"/g).forEach((id) => ids.add(id));
  collectMatches(webviewResults, /check_id:\s*"([^"]+)"/g).forEach((id) => ids.add(id));
  // axe rule names are runtime data. Exercise the prefix guide resolution that
  // must cover every `accessibility.axe.<rule-id>` finding.
  ids.add("accessibility.axe.__dynamic_rule__");

  // Multi-page/session findings are also outside checks/. Their IDs are either
  // supplied to duplicate_field or passed directly to base_result.
  const sessionAnalysis = productionHalf(
    readFileSync(path.join(RUST_SRC, "core/session_analysis.rs"), "utf8"),
  );
  // Match the first string literal in the call rather than a fixed argument
  // list: the leading arguments have changed shape before (`pages` became
  // `comparable, &compared`), and when they did this collector silently
  // stopped seeing `seo.duplicate_h1` while the check was still emitted.
  collectMatches(sessionAnalysis, /duplicate_field\(\s*[^"()]*"([^"]+)"/g).forEach((id) =>
    ids.add(id),
  );
  collectMatches(sessionAnalysis, /base_result\(\s*"([^"]+)"/g).forEach((id) => ids.add(id));

  return Array.from(ids).sort();
}

function collectCodeIssueSlugs(): string[] {
  const registry = readFileSync(
    path.resolve(HERE, "../../src-tauri/crates/engine/src/code_rules.rs"),
    "utf8",
  );
  return Array.from(new Set(collectMatches(registry, /\bd\(\s*"([a-z0-9-]+)"/g))).sort();
}

function collectIssueGuidanceFiles(): string[] {
  return [
    ...walkGuidanceFiles(path.join(HERE, "fix-guides")),
    ...walkGuidanceFiles(path.join(HERE, "code-fix-guides")),
    ...walkGuidanceFiles(path.join(RUST_SRC, "checks")),
    ...walkGuidanceFiles(ENGINE_CHECKS),
    ...walkGuidanceFiles(path.join(RUST_SRC, "core/code_scan")),
    path.join(RUST_SRC, "ai.rs"),
  ];
}

describe("issue fix guide coverage", () => {
  it("resolves every emitted Web Scan and polish issue ID to a baseline", () => {
    const ids = collectWebIssueIds();
    const missing = ids.filter((id) => !getFixGuide(id));

    expect(ids.length).toBeGreaterThan(100);
    expect(missing).toEqual([]);
  });

  it("has no unaccounted Web Scan baselines outside emitted IDs, aliases, or explicit legacy support", () => {
    const ids = collectWebIssueIds();
    const live = (guideId: string) => {
      const candidates = guideId.includes(".") ? [guideId] : [guideId, `polish.${guideId}`];
      const aliases = Object.entries(FIX_GUIDE_ALIASES)
        .filter(([, target]) => target === guideId)
        .map(([alias]) => alias);
      return (
        [...candidates, ...aliases].some((candidate) =>
          ids.some((id) => id === candidate || id.startsWith(`${candidate}.`)),
        ) || LEGACY_FIX_GUIDE_IDS.includes(guideId)
      );
    };
    const stale = FIX_GUIDE_IDS.filter((id) => !live(id));

    expect(stale).toEqual([]);
  });

  it("resolves every emitted Code Scan issue slug to a baseline", () => {
    const slugs = collectCodeIssueSlugs();
    const missing = slugs.filter((slug) => !getCodeFixGuide(slug));

    expect(slugs.length).toBeGreaterThan(160);
    expect(missing).toEqual([]);
  });

  it("has no stale Code Scan baselines outside the authoritative registry", () => {
    const slugs = new Set(collectCodeIssueSlugs());
    const stale = CODE_FIX_GUIDE_IDS.filter((id) => !slugs.has(id));

    expect(stale).toEqual([]);
  });
});

describe("baselines are directions, not teasers", () => {
  const allBaselines = [
    ...FIX_GUIDE_IDS.map((id) => ({ id, guide: getFixGuide(id)! })),
    ...CODE_FIX_GUIDE_IDS.map((id) => ({ id, guide: getCodeFixGuide(id)! })),
  ];

  it("keeps every baseline to at most two self-contained steps of bounded length", () => {
    for (const { id, guide } of allBaselines) {
      expect(guide.steps.length, `${id} step count`).toBeGreaterThanOrEqual(1);
      expect(guide.steps.length, `${id} step count`).toBeLessThanOrEqual(2);
      for (const step of guide.steps) {
        expect(step.length, `${id} step length`).toBeLessThanOrEqual(600);
        expect(step.trim().length, `${id} empty step`).toBeGreaterThan(40);
      }
      expect(guide.effortMinutes, `${id} effortMinutes`).toBeGreaterThan(0);
    }
  });

  it("never sells the deep guide inside baseline content", () => {
    const selling =
      /full guide|deep guide|complete guide|upgrade to (Core|Pro|Plus)|Core plan|Pro plan|Plus plan|paid tier/i;
    const offenders = allBaselines
      .filter(({ guide }) => selling.test(guide.steps.join("\n")))
      .map(({ id }) => id);
    expect(offenders).toEqual([]);
  });

  it("keeps baseline and Rust finding copy free of stale or overconfident advice", () => {
    // The same list guards the deep corpus in SiteCMD-Web (corpus.test.ts).
    // Update both when adding a pattern.
    const banned = [
      {
        pattern: /FID\/INP/,
        reason: "INP is the current Core Web Vital responsiveness metric",
      },
      {
        pattern: /Twitter Card Validator|cards-dev\.twitter\.com/,
        reason: "the old Twitter Card validator is not a dependable user-facing fix target",
      },
      {
        pattern: /srihash\.org/,
        reason: "SRI guidance should use the exact trusted file/version from the app build",
      },
      {
        pattern: /sanitize:\s*true/,
        reason: "marked removed the sanitize option; recommend a maintained sanitizer",
      },
      {
        pattern: /gpt-4-32k|gpt-4o(?:-mini)?/,
        reason: "model names age quickly; issue guidance should point at provider config",
      },
      {
        pattern: /zero-risk/,
        reason: "security guidance should describe compatibility risk accurately",
      },
      {
        pattern: /AI crawlers cannot run JavaScript|invisible to every AI search engine/,
        reason: "crawler rendering behavior varies, so absolute AI crawler claims are misleading",
      },
      {
        pattern:
          /use protocol-relative URLs|or protocol-relative \/\/|protocol-relative \/\/example/,
        reason: "mixed-content fixes should prefer explicit https:// URLs",
      },
      {
        pattern: /most likely to be pulled into AI answers|AI engines look at most/,
        reason: "AI answer selection claims should be framed as signals, not guarantees",
      },
      {
        pattern:
          /If you serve California residents, add|must provide a "Do Not Sell|California AG can fine/,
        reason: "California privacy guidance must include applicability and sale/share context",
      },
      {
        pattern: /free for basic policies|Required if you accept payments|don't need a banner/,
        reason: "legal checklist copy should avoid brittle vendor/pricing claims and blanket rules",
      },
      {
        pattern: /Required by EAA\/ADA|invites legal action/,
        reason: "accessibility statement guidance should avoid overbroad legal claims",
      },
      {
        pattern:
          /GDPR guidelines suggest cookies should not last longer than necessary|Regulators flag excessive cookie lifetimes|Google Analytics' _ga cookie is 2 years/,
        reason: "cookie retention guidance should focus on purpose, policy, consent, and region",
      },
      {
        pattern:
          /Thin pages rarely rank|Search engines will index the other domain|credit another domain|ranking power|Pages without titles are nearly invisible|rank lower|hurt user trust and rankings/,
        reason: "SEO guidance should avoid deterministic ranking claims",
      },
      {
        pattern:
          /silently access the camera|reject obviously malicious patterns|those will never succeed/,
        reason: "security and AI guidance should avoid overstating browser or retry behavior",
      },
    ];

    const offenders: string[] = [];
    for (const file of collectIssueGuidanceFiles()) {
      const source = readFileSync(file, "utf8");
      for (const { pattern, reason } of banned) {
        if (pattern.test(source)) {
          offenders.push(`${path.relative(HERE, file)}: ${reason}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });
});
