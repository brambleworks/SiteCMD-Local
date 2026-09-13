import assert from "node:assert/strict";
import { test } from "node:test";
import { prepareProject } from "../guest/trial-setup.mjs";

test("an unmapped repair never invents a check ID or claims an MCP rejection", async () => {
  const calls = [];
  let closed = false;
  const mcp = {
    request: async () => ({}),
    notify() {},
    close() {
      closed = true;
    },
    async call(name, args) {
      calls.push({ name, args });
      return { content: [{ text: "Code scan complete: execution #1 (complete)" }] };
    },
  };
  await assert.rejects(
    prepareProject(
      { invoke: async () => 9, database: "/isolated.db" },
      { path: "/source" },
      { id: "linkding-asset-sandbox", kind: "repair" },
      { mcp: "/mcp.mjs" },
      { agent: "codex" },
      "mcp",
      () => {},
      { connect: () => mcp },
    ),
    (error) => {
      assert.equal(error.name, "UnmappedHandoffError");
      assert.equal(error.stage, "handoff");
      assert.equal(error.projectId, 9);
      assert.equal(error.response, undefined);
      assert.match(error.message, /no registered SiteCMD check/i);
      return true;
    },
  );
  assert.deepEqual(
    calls.map(({ name }) => name),
    ["run_scan"],
  );
  assert.equal(closed, true);
});

test("a missing repair handoff preserves the product response and never returns a ready project", async () => {
  const calls = [];
  let closed = false;
  const rejected = { isError: true, content: [{ type: "text", text: "Check is not open" }] };
  const mcp = {
    request: async () => ({}),
    notify() {},
    close() {
      closed = true;
    },
    async call(name, args) {
      calls.push({ name, args });
      return name === "run_scan"
        ? { content: [{ text: "Code scan complete: execution #1 (complete)" }] }
        : rejected;
    },
  };
  await assert.rejects(
    prepareProject(
      { invoke: async () => 9, database: "/isolated.db" },
      { path: "/source" },
      { id: "historical-case", kind: "repair", rule: "open-redirect" },
      { mcp: "/mcp.mjs" },
      { agent: "codex" },
      "mcp",
      () => {},
      { connect: () => mcp },
    ),
    (error) => {
      assert.equal(error.stage, "handoff");
      assert.equal(error.projectId, 9);
      assert.deepEqual(error.response, rejected);
      return true;
    },
  );
  assert.deepEqual(
    calls.map(({ name }) => name),
    ["run_scan", "start_fix"],
  );
  assert.equal(calls[1].args.check_id, "code_scan.open-redirect");
  assert.equal(closed, true);
});

test("a confirmatory repair prepares the exact desktop issue occurrence", async () => {
  const calls = [];
  const invokes = [];
  let closed = false;
  const target = {
    checkId: "code_scan.unsafe-html",
    relativePath: "src/render.tsx",
    fingerprint: `sha256:${"a".repeat(64)}`,
  };
  const issue = {
    ...target,
    title: "Raw HTML sink has no recognized local sanitization",
    severity: "high",
    description: "Untrusted markup reaches a raw HTML sink.",
    whyNow: "Active content can execute in the application origin.",
    likelyFix: "Use a safe rendering boundary.",
    sourceExcerpt: "return <div dangerouslySetInnerHTML={{ __html: value }} />;",
    line: 41,
  };
  const desktop = {
    database: "/isolated.db",
    async invoke(command, args) {
      invokes.push({ command, args });
      if (command === "add_project") return 9;
      if (command === "create_fix_attempt")
        return {
          id: 17,
          kickoffPrompt: "SiteCMD prepared fix attempt #17. Read the brief.",
        };
      throw new Error(`Unexpected command ${command}`);
    },
  };
  const mcp = {
    request: async () => ({}),
    notify() {},
    close() {
      closed = true;
    },
    async call(name, args) {
      calls.push({ name, args });
      if (name === "run_scan")
        return { content: [{ text: "Code scan complete: execution #1 (complete)" }] };
      if (name === "get_fix_brief")
        return { content: [{ text: `Where to look\n${target.relativePath}:41` }] };
      throw new Error(`Unexpected tool ${name}`);
    },
  };

  const prepared = await prepareProject(
    desktop,
    { path: "/source" },
    {
      id: "confirmatory-repair",
      kind: "repair",
      confirmatory: true,
      targetFinding: target,
      targetIssue: issue,
    },
    { mcp: "/mcp.mjs" },
    { agent: "codex" },
    "mcp",
    () => {},
    { connect: () => mcp },
  );

  assert.equal(prepared.projectId, 9);
  assert.equal(prepared.attemptId, 17);
  assert.equal(prepared.handoff, "SiteCMD prepared fix attempt #17. Read the brief.");
  assert.match(prepared.brief, /src\/render\.tsx:41/);
  assert.deepEqual(
    calls.map(({ name }) => name),
    ["run_scan", "get_fix_brief"],
  );
  assert.deepEqual(calls[1].args, { attempt_id: 17 });
  assert.deepEqual(invokes[1], {
    command: "create_fix_attempt",
    args: {
      args: {
        projectId: 9,
        envUrl: "http://localhost:4173",
        checkId: target.checkId,
        agentTool: "codex",
        title: issue.title,
        severity: "high",
        description: issue.description,
        whyItMatters: issue.whyNow,
        evidence: {
          fingerprint: target.fingerprint,
          sourceExcerpt: issue.sourceExcerpt,
        },
        manualFix: issue.likelyFix,
        url: "http://localhost:4173",
        detectedStack: null,
        codeLocations: [
          {
            label: "Flagged location",
            path: target.relativePath,
            line: 41,
            reason: "This is the exact location the scanner flagged.",
          },
        ],
        previousFailure: null,
      },
    },
  });
  assert.equal(closed, true);
});

test("a failed desktop scan retains bounded execution diagnostics", async () => {
  const detail = {
    summary: {
      id: 44,
      status: "failed",
      codeStatus: "failed",
      codeDetail: "The report could not be stored",
    },
    runs: [
      {
        id: 8,
        source: "code_scan",
        runKind: "code",
        status: "failed",
        statusDetail: "The report could not be stored",
        diagnostics: { errors: ["storage"] },
        findings: [{ large: "omitted" }],
      },
    ],
  };
  const desktop = {
    database: "/isolated.db",
    async invoke(command, args) {
      if (command === "add_project") return 9;
      assert.equal(command, "get_scan_execution_detail");
      assert.deepEqual(args, { executionId: 44, runId: null });
      return detail;
    },
  };
  const mcp = {
    request: async () => ({}),
    notify() {},
    close() {},
    async call(name) {
      assert.equal(name, "run_scan");
      return { content: [{ text: "Scan request #1 complete: execution #44 (failed)." }] };
    },
  };
  await assert.rejects(
    prepareProject(
      desktop,
      { path: "/source" },
      { id: "failed-scan", kind: "negative_control" },
      { mcp: "/mcp.mjs" },
      { agent: "codex" },
      "normal",
      () => {},
      { connect: () => mcp },
    ),
    (error) => {
      assert.equal(error.stage, "scan");
      assert.equal(error.response.execution.summary.codeDetail, detail.summary.codeDetail);
      assert.equal(error.response.execution.runs[0].statusDetail, detail.runs[0].statusDetail);
      assert.equal(error.response.execution.runs[0].findings, undefined);
      return true;
    },
  );
});
