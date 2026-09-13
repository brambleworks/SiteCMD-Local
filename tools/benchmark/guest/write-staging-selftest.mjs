import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  chmodSync,
  chownSync,
  lstatSync,
  mkdirSync,
  renameSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import { systemCommand } from "./desktop-session.mjs";
import { createWorkspace, closeWorkspace } from "./trial-workspace.mjs";
import { prepareWriteStaging } from "./write-staging.mjs";
import { compareCandidate, readCandidate } from "./trial-snapshot.mjs";

const uid = Number(systemCommand("id", ["-u", "runner"]));
const gid = Number(systemCommand("id", ["-g", "runner"]));
const files = { "source.py": "print('owned permission fixture')\n" };
const fixture = (run) => {
  const workspace = createWorkspace(randomBytes(12).toString("hex"), files);
  try {
    run(workspace);
  } finally {
    closeWorkspace(workspace);
  }
};

fixture((workspace) => {
  const guard = prepareWriteStaging(workspace);
  const staging = path.join(workspace, ".claude/.cc-writes");
  const reader = `
    const { accessSync, constants, readdirSync } = require('node:fs');
    const directory = ${JSON.stringify(staging)};
    readdirSync(directory);
    accessSync(directory, constants.R_OK | constants.X_OK);
    try { accessSync(directory, constants.W_OK); process.exit(1); }
    catch (error) { if (error.code !== 'EACCES') throw error; }
  `;
  systemCommand("sudo", ["-u", "sitecmd", "node", "-e", reader]);
  assert.throws(() => systemCommand("sudo", ["-u", "grader", "ls", staging]), /Permission denied/);
  assert.deepEqual(Object.keys(readCandidate(workspace).files), ["source.py"]);
  const hidden = path.join(staging, "unexpected.py");
  writeFileSync(hidden, "unexpected content");
  const snapshot = readCandidate(workspace);
  assert.equal(compareCandidate(files, snapshot.files, snapshot.violations).passed, false);
  guard.verify();
  chmodSync(staging, 0o700);
  assert.throws(() => guard.verify(), /permissions changed/);
});

fixture((workspace) => {
  const parent = path.join(workspace, ".claude");
  const canary = path.join(workspace, "private");
  mkdirSync(canary, { mode: 0o700 });
  const before = lstatSync(canary);
  symlinkSync(canary, parent);
  assert.throws(() => prepareWriteStaging(workspace), /Unsafe/);
  assert.equal(lstatSync(canary).mode, before.mode);
});

fixture((workspace) => {
  const guard = prepareWriteStaging(workspace);
  chmodSync(path.join(workspace, ".claude"), 0o700);
  assert.throws(() => guard.verify(), /permissions changed/);
});

fixture((workspace) => {
  const parent = path.join(workspace, ".claude");
  mkdirSync(parent, { mode: 0o700 });
  chownSync(parent, uid, gid);
  const guard = prepareWriteStaging(workspace);
  systemCommand("sudo", ["-u", "sitecmd", "ls", path.join(parent, ".cc-writes")]);
  assert.throws(() => systemCommand("sudo", ["-u", "grader", "ls", parent]), /Permission denied/);
  guard.verify();
});

fixture((workspace) => {
  const guard = prepareWriteStaging(workspace);
  const parent = path.join(workspace, ".claude");
  renameSync(parent, path.join(workspace, "old-runtime"));
  mkdirSync(parent);
  chownSync(parent, uid, gid);
  assert.throws(() => guard.verify(), /parent changed/);
});

fixture((workspace) => {
  const guard = prepareWriteStaging(workspace);
  const staging = path.join(workspace, ".claude/.cc-writes");
  renameSync(staging, path.join(workspace, "old-staging"));
  mkdirSync(staging);
  chownSync(staging, uid, gid);
  assert.throws(() => guard.verify(), /directory changed/);
});

console.log(
  JSON.stringify({
    stagingReadOnlyForScanner: true,
    otherUserDenied: true,
    hiddenChangesRejected: true,
    changedPermissionsRejected: true,
    changedParentPermissionsRejected: true,
    privateExistingParentReadableForScanner: true,
    symlinkRejected: true,
    replacementRejected: true,
    modelCalls: 0,
  }),
);
