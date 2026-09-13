import test from "node:test";
import assert from "node:assert/strict";

import { getIssueOccurrences, getIssuesForProject, getLiveScore } from "../dist/db.js";
import { connectInMemory } from "./tools_list_snapshot.test.mjs";
import { ensureProject, makeSeeders, openSchemaFixtureDb } from "./helpers/schema-fixture.mjs";

// Escape every character a regex gives meaning to, not just the dot. A partial
// escape leaves the rest of the identifier free to change what the pattern
// matches, which is the difference between asserting a string and asserting
// whatever that string happens to compile to.
const escapeRegExp = (value) => String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// db.js resolves SITECMD_DB_PATH lazily at first query, so seeding the fixture
// (which sets the env var) after the static imports is safe.
const fixtureDb = openSchemaFixtureDb("sitecmd-mcp-issue-sources-");
const { addWorkItem } = makeSeeders(fixtureDb);

const PROJECT_ID = 901;
const URL = "https://sources.test";

/**
 * One active finding per source the desktop writes into `work_items`:
 * `web_scan` and `code_scan` from scans, `updates` from the dependency engine,
 * `gsc` and `psi` from integration adapters. The desktop's
 * `get_active_issue_groups` filters no source, so the SiteCMD Score counts all
 * of them and `get_issues` must return all of them.
 *
 * Every check id sits in its own dedup family and every row is a distinct
 * (check_id, location) pair, so the score's deduplicated group counts equal
 * this row count severity for severity.
 *
 * These rows carry a fix_prompt so the fix-prompt path is exercised. Real
 * dependency and integration rows do not: every non-scan adapter writes
 * `fix_prompt: None` (updates_adapter.rs, updates_licenses.rs,
 * updates_install_scripts.rs, gsc_adapter.rs, psi_adapter.rs), and
 * loadOpenIssueRows still filters on a non-empty prompt, so in production
 * get_fix_prompts returns scan findings only.
 */
const SEEDED_FINDINGS = [
  {
    source: "web_scan",
    checkId: "security.hsts",
    category: "security",
    severity: "high",
    title: "Missing HSTS header",
  },
  {
    source: "code_scan",
    checkId: "code_scan.unsafe-html",
    category: "security",
    severity: "medium",
    title: "Unsanitized HTML sink",
  },
  {
    source: "updates",
    checkId: "dependencies.outdated-major",
    category: "dependencies",
    severity: "low",
    title: "Dependency is a major version behind",
  },
  {
    source: "updates",
    checkId: "infrastructure.ssl-expiring",
    category: "infrastructure",
    severity: "medium",
    title: "TLS certificate expires soon",
  },
  {
    source: "gsc",
    checkId: "seo.indexing.crawl-error",
    category: "seo",
    severity: "medium",
    title: "Search Console reports crawl errors",
  },
  {
    source: "psi",
    checkId: "performance.lcp",
    category: "performance",
    severity: "low",
    title: "Field LCP is above the good threshold",
  },
];

function severityCounts(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

/** get_scan_score needs a completed web scan artifact before it reports anything. */
function seedWebScan() {
  const startedAt = Date.parse("2026-09-01T00:00:00.000Z");
  const executionId = Number(
    fixtureDb
      .prepare(
        `INSERT INTO scan_executions (
          project_id, environment_url, environment_scope_key, requested_mode, web_focus,
          trigger, admission_class, status, idempotency_key, request_fingerprint,
          started_at, completed_at, web_status
        ) VALUES (?, ?, ?, 'web', 'health', 'manual', 'general_scan', 'complete', ?, ?, ?, ?, 'complete')`,
      )
      .run(
        PROJECT_ID,
        URL,
        URL,
        "issue-sources-web",
        "v1:issue-sources-web",
        startedAt,
        startedAt + 1200,
      ).lastInsertRowid,
  );
  fixtureDb
    .prepare(
      `INSERT INTO scan_runs (
        execution_id, project_id, environment_url, environment_scope_key,
        source, run_kind, status, focus, started_at, completed_at, timestamp_text,
        raw_score, duration_ms, coverage_kind, coverage_json, mode
      ) VALUES (?, ?, ?, ?, 'web_scan', 'single', 'complete', 'health', ?, ?, ?, 81, 1200, 'site', '{"successful":true}', 'live')`,
    )
    .run(
      executionId,
      PROJECT_ID,
      URL,
      URL,
      startedAt,
      startedAt + 1200,
      "2026-09-01T00:00:00.000Z",
    );
}

function seedFixture() {
  ensureProject(fixtureDb, PROJECT_ID);
  fixtureDb
    .prepare(
      `INSERT INTO environments (project_id, url, label, environment)
       VALUES (?, ?, 'Production', 'production')`,
    )
    .run(PROJECT_ID, URL);
  for (const finding of SEEDED_FINDINGS) {
    addWorkItem({
      projectId: PROJECT_ID,
      envUrl: URL,
      source: finding.source,
      signalId: `${finding.checkId}:${finding.source}`,
      checkId: finding.checkId,
      category: finding.category,
      severity: finding.severity,
      title: finding.title,
      fixPrompt: `Fix ${finding.checkId}.`,
    });
  }
  seedWebScan();
  // The snapshot the desktop would persist for exactly these findings.
  const counts = severityCounts(SEEDED_FINDINGS);
  fixtureDb
    .prepare(
      `INSERT INTO score_snapshots (
         project_id, environment_url, overall, critical_count, high_count,
         medium_count, low_count, exploitable_capped, computed_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)`,
    )
    .run(
      PROJECT_ID,
      URL,
      72,
      counts.critical,
      counts.high,
      counts.medium,
      counts.low,
      Date.parse("2026-09-02T00:00:00.000Z"),
    );
}

seedFixture();

async function callTool(name, args) {
  const session = await connectInMemory();
  try {
    const result = await session.client.callTool({ name, arguments: args });
    return result.content[0].text;
  } finally {
    await session.close();
  }
}

test("get_issues returns every work_items source the SiteCMD Score counts", () => {
  const returned = getIssuesForProject(PROJECT_ID, URL)
    .map((issue) => `${issue.source}/${issue.check_id}`)
    .sort();

  assert.deepEqual(
    returned,
    SEEDED_FINDINGS.map((finding) => `${finding.source}/${finding.checkId}`).sort(),
    "get_issues must not drop a source the score counts; an agent reading both tools would see a score that does not add up",
  );
});

// The snapshot this compares against is built by severityCounts over the same
// SEEDED_FINDINGS array, so it proves no severity tier goes missing between the
// two tools, not that MCP reproduces the desktop's counting. Real snapshots
// count dedup families (crates/engine/src/scoring/dedup.rs keys on
// code_rule_id(check_id).unwrap_or(check_id)); the Rust parity tests own that.
test("get_issues loses no severity tier against a snapshot of the same findings", () => {
  const live = getLiveScore(URL);
  assert.ok(live, "the fixture seeds a score snapshot for this environment");

  const returned = getIssuesForProject(PROJECT_ID, URL);
  const counts = severityCounts(returned);

  assert.deepEqual(counts, {
    critical: live.critical_count,
    high: live.high_count,
    medium: live.medium_count,
    low: live.low_count,
  });
  assert.equal(
    returned.length,
    live.critical_count + live.high_count + live.medium_count + live.low_count,
    "each seeded check has exactly one occurrence, so the row count must equal the failing-check total get_scan_score reports",
  );
});

test("get_issue resolves a dependency finding, not only scan findings", () => {
  const occurrences = getIssueOccurrences(PROJECT_ID, URL, "dependencies.outdated-major");
  assert.equal(occurrences.length, 1);
  assert.equal(occurrences[0].source, "updates");
});

test("get_issues labels the source each finding came from", async () => {
  const output = await callTool("get_issues", { url: URL, limit: 100 });

  for (const finding of SEEDED_FINDINGS) {
    assert.match(
      output,
      new RegExp(
        `\\*\\*Check:\\*\\* ${escapeRegExp(finding.checkId)} \\| \\*\\*Source:\\*\\* ${escapeRegExp(finding.source)}\\b`,
      ),
      `${finding.checkId} should name its source so a dependency finding reads differently from a scan finding`,
    );
  }
});

test("the get_fix_prompts query is not source-filtered either", async () => {
  // The seeded rows carry a fix_prompt; real dependency and integration rows
  // do not, so this pins the shared loadOpenIssueRows path rather than
  // claiming production dependency findings ship prompts.
  const output = await callTool("get_fix_prompts", { url: URL, limit: 20 });
  assert.match(output, /dependencies\.outdated-major/);
});

test("min_confidence keeps unrated findings the score counts at full weight", async () => {
  const output = await callTool("get_issues", {
    url: URL,
    min_confidence: "confirmed",
    limit: 100,
  });

  // The seeded rows carry no confidence rating, matching how the dependency
  // and integration adapters write them.
  assert.match(output, /dependencies\.outdated-major/);
  assert.match(output, /seo\.indexing\.crawl-error/);
});

test("get_scan_score does not describe its open-issue count as web and code only", async () => {
  const output = await callTool("get_scan_score", { url: URL });
  const counts = severityCounts(SEEDED_FINDINGS);
  const total = counts.critical + counts.high + counts.medium + counts.low;

  assert.match(output, new RegExp(`\\*\\*Open issues:\\*\\* ${total} failing check`));
  // Name the four kinds of finding that reach work_items, not "every source":
  // uptimerobot, ga4, cloudflare, and plausible are tracked but file none.
  assert.match(
    output,
    /counting web scan, code scan, dependency, and integration findings/,
    "the caption must name what is actually counted, without implying uptime or analytics signals are in the number",
  );
  assert.doesNotMatch(
    output,
    /web and code combined/,
    "the score counts dependency and integration findings too, so the caption must not name only web and code",
  );
});
