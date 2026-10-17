import test from "node:test";
import assert from "node:assert/strict";
import { connectInMemory } from "./tools_list_snapshot.test.mjs";
import { ensureProject, makeSeeders, openSchemaFixtureDb } from "./helpers/schema-fixture.mjs";
import { formatBoundedEntries } from "../dist/output_budget.js";

const fixtureDb = openSchemaFixtureDb("sitecmd-mcp-token-efficiency-");
const { addWorkItem } = makeSeeders(fixtureDb);

function project(id) {
  const url = `https://token-${id}.test`;
  ensureProject(fixtureDb, id);
  fixtureDb
    .prepare(
      `INSERT INTO environments (project_id, url, label, environment)
     VALUES (?, ?, 'Production', 'production')`,
    )
    .run(id, url);
  return url;
}

async function withClient(run) {
  const session = await connectInMemory();
  try {
    await run(async (name, args) => {
      const result = await session.client.callTool({ name, arguments: args });
      assert.ok(!result.isError, result.content[0].text);
      return result.content[0].text;
    });
  } finally {
    await session.close();
  }
}

test("issue summaries are compact and full descriptions remain available on demand", async () => {
  const url = project(1601);
  for (let index = 0; index < 25; index += 1) {
    addWorkItem({
      projectId: 1601,
      envUrl: url,
      checkId: `performance.summary-${index}`,
      description: `${"Measured finding. ".repeat(100)}Full detail marker.`,
      fixPrompt: "A full fix prompt.",
    });
  }
  await withClient(async (call) => {
    const summary = await call("get_issues", { url });
    assert.match(summary, /^25 of 25 open issue/);
    assert.ok(summary.length < 17000, `${summary.length} characters`);
    assert.doesNotMatch(summary, /Full detail marker|A full fix prompt/);
    const detail = await call("get_issue", { url, check_id: "performance.summary-0" });
    assert.match(detail, /Full detail marker/);
    assert.match(detail, /A full fix prompt/);
  });
});

test("bounded issue pages traverse every matching issue without skipping or repeating", async () => {
  const url = project(1602);
  for (let index = 0; index < 12; index += 1) {
    addWorkItem({
      projectId: 1602,
      envUrl: url,
      checkId: `security.page-${index}`,
      category: "security",
      title: `${index} ${"&".repeat(500)}`,
      description: "<&>".repeat(1000),
      pageUrl: `${url}/${"&".repeat(500)}`,
    });
  }
  addWorkItem({ projectId: 1602, envUrl: url, checkId: "seo.excluded", category: "seo" });
  await withClient(async (call) => {
    const seen = new Set();
    let offset = 0;
    for (let page = 0; page < 12; page += 1) {
      const output = await call("get_issues", { url, category: "security", limit: 100, offset });
      assert.ok(output.length < 17500, `${output.length} characters`);
      assert.doesNotMatch(output, /seo.excluded/);
      assert.equal(output.match(/<\/sitecmd_untrusted_scan_data>/g)?.length, 1);
      for (const [, id] of output.matchAll(/\*\*Check:\*\* (security\.page-\d+)/g)) {
        assert.ok(!seen.has(id), `repeated ${id}`);
        seen.add(id);
      }
      const next = output.match(/Next page: call get_issues with offset=(\d+)/);
      if (!next) break;
      assert.ok(Number(next[1]) > offset);
      offset = Number(next[1]);
    }
    assert.equal(seen.size, 12);
    const exhausted = await call("get_issues", { url, category: "security", offset: 12 });
    assert.match(exhausted, /^0 of 12/);
    assert.doesNotMatch(exhausted, /Next page/);
  });
});

test("exact duplicate prompts collapse but distinct checks and occurrence guidance survive", async () => {
  const url = project(1603);
  for (let index = 0; index < 20; index += 1) {
    addWorkItem({
      projectId: 1603,
      envUrl: url,
      signalId: `duplicate-${index}`,
      checkId: "security.shared",
      title: "Shared fix",
      fixPrompt: "Apply shared guidance.",
    });
  }
  addWorkItem({
    projectId: 1603,
    envUrl: url,
    signalId: "distinct-occurrence",
    checkId: "security.shared",
    title: "Shared fix",
    fixPrompt: "Fix src/other.ts.",
  });
  addWorkItem({
    projectId: 1603,
    envUrl: url,
    checkId: "security.other",
    title: "Shared fix",
    fixPrompt: "Apply shared guidance.",
  });
  await withClient(async (call) => {
    const output = await call("get_fix_prompts", { url });
    assert.match(output, /^3 of 3 fix prompt/);
    assert.match(output, /Identical prompts are shown once/);
    assert.equal(output.match(/Apply shared guidance/g)?.length, 2);
    assert.match(output, /Fix src\/other.ts/);
    const targeted = await call("get_fix_prompts", { url, check_id: "security.shared", limit: 1 });
    assert.match(targeted, /Next page: call get_fix_prompts with offset=1/);
    const next = await call("get_fix_prompts", { url, check_id: "security.shared", offset: 1 });
    assert.match(next, /Fix src\/other.ts/);
    assert.doesNotMatch(next, /Next page/);
  });
});

test("prompt size limits preserve whole later entries for the next page", async () => {
  const url = project(1604);
  for (let index = 0; index < 5; index += 1) {
    addWorkItem({
      projectId: 1604,
      envUrl: url,
      checkId: `security.large-${index}`,
      fixPrompt: `Prompt ${index}: ${"guidance ".repeat(1300)}END-${index}`,
    });
  }
  await withClient(async (call) => {
    const first = await call("get_fix_prompts", { url });
    assert.ok(first.length < 25500, `${first.length} characters`);
    assert.match(first, /^2 of 5 fix prompt/);
    assert.match(first, /END-0/);
    assert.match(first, /END-1/);
    assert.doesNotMatch(first, /Prompt 2/);
    assert.match(first, /offset=2/);
    const next = await call("get_fix_prompts", { url, offset: 2 });
    assert.match(next, /Prompt 2/);
    assert.match(next, /END-2/);
    assert.doesNotMatch(next, /Prompt 0/);
  });
});

test("an oversized first entry preserves Unicode and marks the bounded result", () => {
  const output = formatBoundedEntries(["abc😀tail"], (value) => value, 8);
  assert.ok(output.body.length <= 8);
  assert.ok(output.body.isWellFormed());
  assert.equal(output.body, "abc\n...");
  assert.equal(output.count, 1);
  assert.equal(output.shortened, true);
});
