import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it } from "vitest";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const SCRIPTS = path.join(ROOT, ".github", "scripts", "release");
const VERSION = "1.5.4";
const SOURCE_COMMIT = "0123456789abcdef0123456789abcdef01234567";
const TARGETS = ["darwin-universal", "linux-aarch64", "linux-x86_64", "windows-x86_64"];
const LINUX_ARM = "linux-aarch64";
const archiveFor = (target) =>
  `sitecmd-cli_${VERSION}_${target}.${target.startsWith("windows") ? "zip" : "tar.gz"}`;
const temporaryRoots = [];

const sha256 = (content) => createHash("sha256").update(content).digest("hex");
const fileHash = (file) => sha256(fs.readFileSync(file));

function writeChecksums(dir) {
  const lines = fs
    .readdirSync(dir)
    .filter((name) => name !== "SHA256SUMS")
    .sort()
    .map((name) => `${fileHash(path.join(dir, name))}  ${name}\n`);
  fs.writeFileSync(path.join(dir, "SHA256SUMS"), lines.join(""));
}

function writeLeg(root, target, extraFields) {
  const dir = path.join(root, "unsigned", `unsigned-platform-${target}`);
  const archive = archiveFor(target);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, archive), `${target} ${archive}\n`);
  fs.writeFileSync(
    path.join(dir, `${archive}.sha256`),
    `${fileHash(path.join(dir, archive))}  ${archive}\n`,
  );
  fs.writeFileSync(
    path.join(dir, "fragment.json"),
    `${JSON.stringify({ target, cli_archive: archive, ...extraFields })}\n`,
  );
  writeChecksums(dir);
}

function createUnsignedPayload({ cliTarget = LINUX_ARM, extraFields } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-release-payload-"));
  temporaryRoots.push(root);
  fs.mkdirSync(path.join(root, "release-candidate"));
  const manifest = path.join(root, "release-candidate", "manifest.json");
  const lock = path.join(root, "engine.lock");
  fs.writeFileSync(lock, "{}\n");
  fs.writeFileSync(
    manifest,
    `${JSON.stringify({ source_commit: SOURCE_COMMIT, version: VERSION, engine_lock_sha256: fileHash(lock) })}\n`,
  );
  for (const target of TARGETS) {
    if (target === LINUX_ARM) writeLeg(root, cliTarget, extraFields);
    else writeLeg(root, target);
  }
  return { root, candidateHash: fileHash(manifest) };
}

function run(script, cwd, env) {
  return spawnSync("bash", [path.join(SCRIPTS, script)], {
    cwd,
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function stage(payload) {
  const result = run("stage-signer-inputs.sh", payload.root, {
    EXPECTED_CANDIDATE_HASH: payload.candidateHash,
    EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
  });
  expect(result.stderr).toBe("");
  expect(result.status).toBe(0);
}

const planLines = (root, name) =>
  fs
    .readFileSync(path.join(root, name), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => line.split("\t"));

function sign(root, { skipCliArchive = false } = {}) {
  const signingInput = path.join(root, "signing-input");
  const signed = [];
  const signFile = (target, name) => {
    const file = path.join(signingInput, target, name);
    fs.writeFileSync(`${file}.sig`, Buffer.from(`signature of ${name}`).toString("base64"));
    signed.push(file);
  };
  for (const [target, archive] of planLines(root, "cli-signing-plan.tsv")) {
    if (skipCliArchive && target === LINUX_ARM)
      signed.push(path.join(signingInput, target, archive));
    else signFile(target, archive);
  }
  const manifest = signed
    .map((file) => `${fileHash(file)}  ${path.basename(file)}\n`)
    .sort((left, right) => left.slice(66).localeCompare(right.slice(66)))
    .join("");
  fs.writeFileSync(path.join(signingInput, "SHA256SUMS"), manifest);
  fs.writeFileSync(path.join(signingInput, "SHA256SUMS.minisig"), "manifest signature");
  fs.writeFileSync(
    path.join(signingInput, "SHA256SUMS.sig"),
    Buffer.from("manifest signature").toString("base64"),
  );
}

function record(payload) {
  return run("record-signed-payload.sh", payload.root, {
    CANDIDATE_HASH: payload.candidateHash,
    SOURCE_COMMIT,
  });
}

function prepareVerifier(root) {
  fs.renameSync(path.join(root, "signed-release-payload"), path.join(root, "payload"));
  const setupAction = path.join(root, ".github", "actions", "setup-sitecmd");
  fs.mkdirSync(setupAction, { recursive: true });
  fs.writeFileSync(path.join(setupAction, "updater-public-key.pub"), "updater public key\n");
  const verifierDir = path.join(root, ".github", "updater-verifier", "target", "release");
  fs.mkdirSync(verifierDir, { recursive: true });
  const log = path.join(root, "verifier.log");
  fs.writeFileSync(
    path.join(verifierDir, "sitecmd-updater-verifier"),
    `#!/bin/sh\nprintf '%s\\n' "$2" >> "${log}"\n`,
    { mode: 0o755 },
  );
  return log;
}

function verify(payload, target) {
  return run("verify-signed-payload.sh", payload.root, {
    TARGET: target,
    EXPECTED_CANDIDATE_HASH: payload.candidateHash,
    EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
  });
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

describe("release payload scripts", { timeout: 20_000 }, () => {
  it("stages exactly the four CLI archives with their checksum sidecars", () => {
    // A missing or unexpected payload can enter the CLI signing plan.
    const payload = createUnsignedPayload();
    stage(payload);
    expect(planLines(payload.root, "cli-signing-plan.tsv")).toEqual(
      TARGETS.map((target) => [target, archiveFor(target)]),
    );
    for (const target of TARGETS) {
      const archive = archiveFor(target);
      expect(fs.readdirSync(path.join(payload.root, "signing-input", target)).sort()).toEqual(
        [archive, `${archive}.sha256`, "fragment.json"].sort(),
      );
    }
  });

  it("rejects a fragment for a target the release does not ship", () => {
    // An unexpected platform archive can reach the production signer.
    const payload = createUnsignedPayload({ cliTarget: "linux-riscv64" });
    const result = run("stage-signer-inputs.sh", payload.root, {
      EXPECTED_CANDIDATE_HASH: payload.candidateHash,
      EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout + result.stderr).toContain("Unexpected CLI signer target: linux-riscv64");
    expect(fs.existsSync(path.join(payload.root, "signing-input", "linux-riscv64"))).toBe(false);
  });

  it("rejects a second signer input for the same target", () => {
    // Duplicate signer inputs can overwrite the approved archive for a target.
    const payload = createUnsignedPayload();
    const original = path.join(payload.root, "unsigned", "unsigned-platform-linux-aarch64");
    fs.cpSync(original, `${original}-duplicate`, { recursive: true });
    const result = run("stage-signer-inputs.sh", payload.root, {
      EXPECTED_CANDIDATE_HASH: payload.candidateHash,
      EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout + result.stderr).toContain("Duplicate CLI signer target: linux-aarch64");
  });

  it("rejects a CLI fragment carrying desktop artifact metadata", () => {
    // Desktop metadata can enter a CLI signing plan.
    const payload = createUnsignedPayload({ extraFields: { dmg_name: "SiteCMD_arm.dmg" } });
    const result = run("stage-signer-inputs.sh", payload.root, {
      EXPECTED_CANDIDATE_HASH: payload.candidateHash,
      EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
    });
    expect(result.status).not.toBe(0);
    expect(result.stdout + result.stderr).toContain("Unexpected fields in CLI signer input");
  });

  it("records provenance and archive signatures for every CLI target", () => {
    // Signed archives can lose the source commit or candidate that authorized them.
    const payload = createUnsignedPayload();
    stage(payload);
    sign(payload.root);
    const result = record(payload);

    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    for (const target of TARGETS) {
      const dir = path.join(payload.root, "signed-release-payload", target);
      const fragment = JSON.parse(fs.readFileSync(path.join(dir, "fragment.json"), "utf8"));
      const archive = archiveFor(target);
      expect(fragment).toEqual({
        target,
        cli_archive: archive,
        candidate_hash: payload.candidateHash,
        source_commit: SOURCE_COMMIT,
      });
      expect(fs.readFileSync(path.join(dir, "SHA256SUMS"), "utf8")).toContain(`  ${archive}.sig\n`);
    }
    expect(
      fs.existsSync(path.join(payload.root, "signed-release-payload", "SHA256SUMS.minisig")),
    ).toBe(true);
  });

  it("refuses to record a CLI leg whose archive was not signed", () => {
    // An archive can reach verification without a signature.
    const payload = createUnsignedPayload();
    stage(payload);
    sign(payload.root, { skipCliArchive: true });

    const result = record(payload);

    expect(result.status).not.toBe(0);
    expect(fs.existsSync(path.join(payload.root, "signed-release-payload", LINUX_ARM))).toBe(false);
  });

  it("verifies each CLI archive and the release checksum manifest", () => {
    // A platform can skip the signed archive or release checksum verification.
    const payload = createUnsignedPayload();
    stage(payload);
    sign(payload.root);
    expect(record(payload).status).toBe(0);
    const log = prepareVerifier(payload.root);

    for (const target of TARGETS) {
      const result = verify(payload, target);
      expect(result.stderr).toBe("");
      expect(result.status).toBe(0);
      expect(fs.readFileSync(log, "utf8")).toBe(
        `payload/${target}/${archiveFor(target)}\npayload/SHA256SUMS\n`,
      );
      fs.unlinkSync(log);
    }
  });
});
