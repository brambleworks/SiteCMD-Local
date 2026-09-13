import test from "node:test";
import assert from "node:assert/strict";

import { connectInMemory } from "./tools_list_snapshot.test.mjs";
import { openSchemaFixtureDb } from "./helpers/schema-fixture.mjs";

openSchemaFixtureDb("sitecmd-mcp-annotations-");

const WRITERS = new Set(["request_verification", "start_fix", "run_scan"]);

test("every tool carries a title and honest read-only annotations", async () => {
  const session = await connectInMemory();
  try {
    const { tools } = await session.client.listTools();
    assert.ok(tools.length >= 17, `expected the full tool set, got ${tools.length}`);
    for (const tool of tools) {
      assert.ok(tool.title, `${tool.name} needs a title`);
      assert.equal(
        tool.annotations?.readOnlyHint,
        !WRITERS.has(tool.name),
        `${tool.name} readOnlyHint must match whether it writes the local database`,
      );
      assert.equal(tool.annotations?.destructiveHint, false, `${tool.name} never destroys data`);
      assert.equal(tool.annotations?.openWorldHint, false, `${tool.name} reads a local database`);
      assert.equal(tool.annotations?.idempotentHint, true, `${tool.name} repeats safely`);
    }
  } finally {
    await session.close();
  }
});

test("correlation tools resolve a project from its URL", async () => {
  const session = await connectInMemory();
  try {
    const result = await session.client.callTool({
      name: "get_causal_graph",
      arguments: { url: "https://no-such-project.test" },
    });
    assert.equal(result.isError, true);
    assert.match(
      result.content[0].text,
      /No SiteCMD project is linked to https:\/\/no-such-project\.test/,
    );
  } finally {
    await session.close();
  }
});
