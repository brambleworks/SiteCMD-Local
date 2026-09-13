import test from "node:test";
import assert from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { connectInMemory } from "./tools_list_snapshot.test.mjs";
import { ensureProject, makeSeeders, openSchemaFixtureDb } from "./helpers/schema-fixture.mjs";

const db = openSchemaFixtureDb("sitecmd-mcp-fix-target-");
const { addWorkItem, setIssueState } = makeSeeders(db);
const envUrl = "https://target.test";
const checkId = "code_scan.unsafe-html";

function seed(projectId, line, overrides = {}) {
  ensureProject(db, projectId);
  addWorkItem({
    projectId,
    envUrl,
    checkId,
    signalId: `${checkId}:web/logic.js:${line}`,
    source: "code_scan",
    relativePath: "web/logic.js",
    line,
    ...overrides,
  });
}

async function startFix(projectId, target) {
  const session = await connectInMemory();
  try {
    return await session.client.callTool({
      name: "start_fix",
      arguments: { project_id: projectId, url: envUrl, check_id: checkId, wait: false, ...target },
    });
  } finally {
    await session.close();
  }
}

test("start_fix rejects a missing occurrence instead of queuing another line", async () => {
  seed(1, 241);
  const result = await startFix(1, { relative_path: "web/logic.js", line: 346 });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /occurrence.*get_issue/);
  assert.equal(db.prepare("SELECT count(*) AS count FROM agent_requests").get().count, 0);
});

test("start_fix requires a line for an ambiguous path", async () => {
  seed(3, 241);
  seed(3, 346);
  const result = await startFix(3, { relative_path: "web/logic.js" });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /More than one.*line/);
  assert.equal(
    db.prepare("SELECT count(*) AS count FROM agent_requests WHERE project_id = 3").get().count,
    0,
  );
});

test("a path-only request pins the sole occurrence's line", async () => {
  seed(4, 346);
  const result = await startFix(4, { relative_path: "web/logic.js" });
  assert.notEqual(result.isError, true, result.content[0].text);
  assert.equal(
    db.prepare("SELECT target_line FROM agent_requests WHERE project_id = 4").get().target_line,
    346,
  );
});

test("an explicit null line selects a file-level occurrence, not another line", async () => {
  seed(5, null);
  seed(5, 346);
  const result = await startFix(5, { relative_path: "web/logic.js", line: null });
  assert.notEqual(result.isError, true, result.content[0].text);
  const request = db.prepare("SELECT * FROM agent_requests WHERE project_id = 5").get();
  assert.equal(request.target_relative_path, "web/logic.js");
  assert.equal(request.target_line, null);
});

test("omitting a location preserves desktop-selected requests", async () => {
  seed(6, 241);
  seed(6, 346);
  const result = await startFix(6, {});
  assert.notEqual(result.isError, true, result.content[0].text);
  const request = db.prepare("SELECT * FROM agent_requests WHERE project_id = 6").get();
  assert.equal(request.target_relative_path, null);
  assert.equal(request.target_line, null);
});

test("a mapped Code Scan check keeps its canonical identity and selected location", async () => {
  seed(7, 346, { checkId: "security.hsts" });
  const result = await startFix(7, {
    check_id: "security.hsts",
    relative_path: "web/logic.js",
    line: 346,
  });
  assert.notEqual(result.isError, true, result.content[0].text);
  const request = db.prepare("SELECT * FROM agent_requests WHERE project_id = 7").get();
  assert.equal(request.check_id, "security.hsts");
  assert.equal(request.target_line, 346);
});

test("a matching location in another environment does not satisfy a request", async () => {
  seed(8, 241);
  seed(8, 346, { envUrl: "https://other.test" });
  const result = await startFix(8, { relative_path: "web/logic.js", line: 346 });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /No open Code Scan occurrence/);
});

test("a matching Web Scan finding cannot satisfy a Code Scan location selector", async () => {
  seed(9, 346, { source: "web_scan", checkId: "security.hsts" });
  const result = await startFix(9, {
    check_id: "security.hsts",
    relative_path: "web/logic.js",
    line: 346,
  });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /No open Code Scan occurrence/);
});

test("resolved and ignored occurrences cannot start a fix", async () => {
  seed(10, 241);
  seed(10, 346, { resolvedAt: Date.now() });
  const target = { relative_path: "web/logic.js", line: 346 };
  assert.equal((await startFix(10, target)).isError, true);
  seed(11, 346);
  setIssueState({ projectId: 11, envUrl, checkId, status: "ignored" });
  assert.equal((await startFix(11, target)).isError, true);
});

test("invalid locations cannot queue requests", async () => {
  seed(12, 346);
  for (const target of [
    { line: 346 },
    { line: null },
    { relative_path: "", line: 346 },
    { relative_path: "web/logic.js", line: 0 },
    { relative_path: "web/logic.js", line: -1 },
    { relative_path: "web/logic.js", line: 1.5 },
    { relative_path: "web/logic.js", line: 4294967296 },
    { relative_path: "../web/logic.js", line: 346 },
    { relative_path: "/web/logic.js", line: 346 },
  ]) {
    const result = await startFix(12, target);
    assert.equal(result.isError, true, JSON.stringify(target));
  }
  assert.equal(
    db.prepare("SELECT count(*) AS count FROM agent_requests WHERE project_id = 12").get().count,
    0,
  );
});

test("start_fix queues the exact occurrence when a check has several lines", async () => {
  seed(2, 241);
  seed(2, 346);
  const result = await startFix(2, { relative_path: "web/logic.js", line: 346 });
  assert.notEqual(result.isError, true, result.content[0].text);
  const request = db.prepare("SELECT * FROM agent_requests WHERE project_id = ?").get(2);
  assert.equal(request.target_relative_path, "web/logic.js");
  assert.equal(request.target_line, 346);
});

test("repository suppressions prevent an explicitly targeted request", async () => {
  const root = join(dirname(process.env.SITECMD_DB_PATH), "suppressed-project");
  mkdirSync(join(root, ".sitecmd"), { recursive: true });
  writeFileSync(
    join(root, ".sitecmd", "config.json"),
    JSON.stringify({
      version: 1,
      url: envUrl,
      name: "Suppressed project",
      code_scan: {
        suppressions: [
          { match: { rule: checkId, path: "web/logic.js" }, reason: "Intentional test example" },
        ],
      },
    }),
  );
  ensureProject(db, 13, { path: root });
  seed(13, 346, {
    detailJson: JSON.stringify({
      id: "unsafe-html:web/logic.js:346",
      checkId,
      relativePath: "web/logic.js",
      sourceExcerpt: "providerView.innerHTML = loc.provider;",
    }),
  });
  const result = await startFix(13, { relative_path: "web/logic.js", line: 346 });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /No open issue/);
  assert.equal(
    db.prepare("SELECT count(*) AS count FROM agent_requests WHERE project_id = 13").get().count,
    0,
  );
});

test("an occurrence in another project cannot satisfy the explicit project selection", async () => {
  seed(14, 241);
  seed(15, 346);
  const result = await startFix(14, { relative_path: "web/logic.js", line: 346 });
  assert.equal(result.isError, true);
  assert.match(result.content[0].text, /No open Code Scan occurrence/);
});
