import assert from "node:assert/strict";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { prepareRepositoryAgentRuntime } from "../guest/repository-agent-runtime.mjs";

test("Whoogle agent runtime copies mutable application storage outside the workspace", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "sitecmd-agent-runtime-"));
  const id = "a".repeat(24);
  const workspace = path.join(root, "workspaces", id);
  const channel = path.join(root, "channels", id);
  mkdirSync(path.join(workspace, "app", "static", "settings"), { recursive: true });
  mkdirSync(channel, { recursive: true });
  writeFileSync(path.join(workspace, "app", "static", "settings", "fixture.json"), "{}\n");
  const result = prepareRepositoryAgentRuntime({
    item: { id: "whoogle-named-config-path", repositoryRuntime: {} },
    workspace,
    channel,
    owner: { uid: process.getuid(), gid: process.getgid() },
  });
  assert.equal(
    readFileSync(path.join(result.directory, "static", "settings", "fixture.json"), "utf8"),
    "{}\n",
  );
  assert.ok(existsSync(path.join(result.directory, "config")));
  assert.equal(existsSync(path.join(workspace, "app", "static", "config")), false);
});

test("OneKey's grader-only runtime is not exposed to the repair agent", () => {
  assert.equal(
    prepareRepositoryAgentRuntime({
      item: {
        id: "onekey-http-client-tls-verification",
        repositoryRuntime: { directory: "/private/grader/runtime" },
      },
    }),
    null,
  );
});
