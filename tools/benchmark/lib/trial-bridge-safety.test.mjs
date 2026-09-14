import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { bridgeRequest } from "../guest/bridge-client.mjs";
import { createTrialBridge } from "../guest/trial-bridge.mjs";
import { requestLimit, responseLimit } from "../guest/bridge-files.mjs";

async function fixture(t, options = {}) {
  const directory = mkdtempSync(path.join(tmpdir(), "sitecmd-channel-"));
  const channel = path.join(directory, "channel");
  const failures = [];
  const bridge = await createTrialBridge({
    channel,
    arm: "normal",
    submit: async (summary) => summary,
    ...options,
    onError: (error) => failures.push(error),
  });
  t.after(async () => {
    try {
      if (failures.length) await assert.rejects(bridge.close(), failures[0]);
      else await bridge.close();
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
  return { channel, directory, failures };
}

async function until(check) {
  const deadline = Date.now() + 3000;
  while (!check()) {
    assert.ok(Date.now() < deadline, "Bridge condition timed out");
    await delay(10);
  }
}

function message(channel, overrides = {}) {
  const id = randomBytes(16).toString("hex");
  return {
    id,
    request: `${channel}/requests/${id}.json`,
    response: `${channel}/responses/${id}.json`,
    bytes: JSON.stringify({
      version: 1,
      id,
      route: "/submit",
      body: { summary: "candidate" },
      ...overrides,
    }),
  };
}

test("malformed, linked, oversized, and misidentified requests never reach the controller", async (t) => {
  let submissions = 0;
  const { channel, directory, failures } = await fixture(t, { submit: async () => ++submissions });
  const target = path.join(directory, "outside.json");
  writeFileSync(target, "outside data");
  for (const kind of ["malformed", "identity", "symlink", "hardlink", "oversized", "directory"]) {
    const entry = message(channel, kind === "identity" ? { id: "another request" } : {});
    if (kind === "symlink") symlinkSync(target, entry.request);
    else if (kind === "hardlink") linkSync(target, entry.request);
    else if (kind === "directory") mkdirSync(entry.request);
    else
      writeFileSync(
        entry.request,
        kind === "oversized"
          ? "x".repeat(requestLimit + 1)
          : kind === "malformed"
            ? "{"
            : entry.bytes,
      );
    await until(() => existsSync(entry.response));
    assert.equal(JSON.parse(readFileSync(entry.response)).ok, false);
    if (kind === "directory") {
      await until(() => failures.length > 0);
      assert.match(failures[0].message, /EISDIR|EPERM/);
    }
  }
  assert.equal(submissions, 0);
  assert.equal(readFileSync(target, "utf8"), "outside data");
});

test("duplicate publication cannot submit the same candidate twice", async (t) => {
  let submissions = 0;
  const { channel } = await fixture(t, { submit: async () => ++submissions });
  const entry = message(channel);
  writeFileSync(entry.request, entry.bytes);
  await until(() => existsSync(entry.response));
  writeFileSync(entry.request, entry.bytes);
  await until(() => !existsSync(entry.request));
  assert.equal(submissions, 1);
  assert.equal(JSON.parse(readFileSync(entry.response)).value, 1);
});

test("sandbox protection directories and temporary files are not protocol requests", async (t) => {
  const { channel, failures } = await fixture(t);
  mkdirSync(`${channel}/requests/.agents`);
  mkdirSync(`${channel}/requests/.codex`);
  writeFileSync(`${channel}/requests/runtime-marker`, "not a request");
  const pending = message(channel);
  writeFileSync(`${pending.request}.tmp`, "{");
  assert.equal(
    await bridgeRequest(channel, "/submit", { summary: "valid request" }, { timeoutMs: 1000 }),
    "valid request",
  );
  assert.deepEqual(failures, []);
});

test("oversized responses fail without exposing a partial result", async (t) => {
  const { channel } = await fixture(t, { submit: async () => "x".repeat(responseLimit) });
  await assert.rejects(bridgeRequest(channel, "/submit", {}), /response exceeds/);
});

test("request queues and total calls are bounded", async (t) => {
  const queue = await fixture(t);
  for (let index = 0; index < 129; index++) {
    const entry = message(queue.channel);
    writeFileSync(entry.request, entry.bytes);
  }
  await until(() => queue.failures.length > 0);
  assert.match(queue.failures[0].message, /queue limit/);
  const calls = await fixture(t);
  for (let index = 0; index < 256; index += 64)
    await Promise.all(
      Array.from({ length: 64 }, () =>
        bridgeRequest(calls.channel, "/submit", { summary: "test" }),
      ),
    );
  const entry = message(calls.channel);
  writeFileSync(entry.request, entry.bytes);
  await until(() => calls.failures.length > 0);
  assert.match(calls.failures[0].message, /count limit/);
});

test("the client bounds requests, rejects mismatched responses, and times out", async (t) => {
  const { channel } = await fixture(t);
  await assert.rejects(
    bridgeRequest(channel, "/submit", { summary: "x".repeat(requestLimit) }),
    /byte limit/,
  );
  const other = path.join(channel, "offline");
  mkdirSync(other);
  for (const name of ["requests", "responses"]) mkdirSync(`${other}/${name}`);
  await assert.rejects(bridgeRequest(other, "/submit", {}, { timeoutMs: 50 }), /timed out/);
  assert.deepEqual(readdirSync(`${other}/requests`), []);
  const pending = bridgeRequest(other, "/submit", {}, { timeoutMs: 1000 });
  const rejected = assert.rejects(pending, /response identity/);
  const [name] = readdirSync(`${other}/requests`);
  writeFileSync(
    `${other}/responses/${name}`,
    JSON.stringify({ version: 1, id: "wrong", ok: true, value: "forged" }),
  );
  await rejected;
});

test("failed snapshot validation never forwards a verification request", async (t) => {
  let forwarded = false;
  const { channel } = await fixture(t, {
    arm: "mcp",
    submit: async () => {
      throw new Error("Snapshot rejected");
    },
    mcp: {
      request: async () => {
        forwarded = true;
      },
    },
  });
  await assert.rejects(
    bridgeRequest(channel, "/mcp", {
      jsonrpc: "2.0",
      id: 1,
      method: "tools/call",
      params: { name: "request_verification" },
    }),
    /Snapshot rejected/,
  );
  assert.equal(forwarded, false);
});
