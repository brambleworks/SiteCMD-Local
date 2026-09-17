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
const UPDATER_LEGS = [
  {
    target: "darwin-universal",
    filename: `SiteCMD_${VERSION}_universal.app.tar.gz`,
    dmg_name: `SiteCMD_${VERSION}_universal.dmg`,
    archive: `sitecmd-cli_${VERSION}_darwin-universal.tar.gz`,
  },
  {
    target: "linux-x86_64",
    filename: `SiteCMD_${VERSION}_amd64.AppImage`,
    archive: `sitecmd-cli_${VERSION}_linux-x86_64.tar.gz`,
  },
  {
    target: "windows-x86_64",
    filename: `SiteCMD_${VERSION}_x64-setup.exe`,
    archive: `sitecmd-cli_${VERSION}_windows-x86_64.zip`,
  },
];
const CLI_LEG = { target: "linux-aarch64", archive: `sitecmd-cli_${VERSION}_linux-aarch64.tar.gz` };
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

function writeLeg(root, leg, fragment) {
  const dir = path.join(root, "unsigned", `unsigned-platform-${leg.target}`);
  fs.mkdirSync(dir, { recursive: true });
  for (const name of [leg.filename, leg.dmg_name, leg.archive].filter(Boolean)) {
    fs.writeFileSync(path.join(dir, name), `${leg.target} ${name}\n`);
  }
  fs.writeFileSync(
    path.join(dir, `${leg.archive}.sha256`),
    `${fileHash(path.join(dir, leg.archive))}  ${leg.archive}\n`,
  );
  fs.writeFileSync(path.join(dir, "fragment.json"), `${JSON.stringify(fragment)}\n`);
  writeChecksums(dir);
}

function createUnsignedPayload({ cliTarget = CLI_LEG.target, cliDmg = false } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-release-payload-"));
  temporaryRoots.push(root);
  fs.mkdirSync(path.join(root, "release-candidate"));
  const manifest = path.join(root, "release-candidate", "manifest.json");
  fs.writeFileSync(
    manifest,
    `${JSON.stringify({ source_commit: SOURCE_COMMIT, version: VERSION })}\n`,
  );
  for (const leg of UPDATER_LEGS) {
    writeLeg(root, leg, {
      target: leg.target,
      filename: leg.filename,
      cli_archive: leg.archive,
      ...(leg.dmg_name ? { dmg_name: leg.dmg_name } : {}),
    });
  }
  writeLeg(
    root,
    { ...CLI_LEG, target: cliTarget, dmg_name: cliDmg ? "SiteCMD_arm.dmg" : undefined },
    {
      target: cliTarget,
      cli_archive: CLI_LEG.archive,
      ...(cliDmg ? { dmg_name: "SiteCMD_arm.dmg" } : {}),
    },
  );
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
  for (const [target, filename, archive] of planLines(root, "signing-plan.tsv")) {
    signFile(target, filename);
    signFile(target, archive);
    const fragment = JSON.parse(fs.readFileSync(path.join(signingInput, target, "fragment.json")));
    if (fragment.dmg_name) signed.push(path.join(signingInput, target, fragment.dmg_name));
  }
  for (const [target, archive] of planLines(root, "cli-signing-plan.tsv")) {
    if (skipCliArchive) signed.push(path.join(signingInput, target, archive));
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
  const config = path.join(root, "apps", "desktop", "src-tauri");
  fs.mkdirSync(config, { recursive: true });
  fs.writeFileSync(
    path.join(config, "tauri.conf.json"),
    JSON.stringify({
      plugins: { updater: { pubkey: Buffer.from("updater public key").toString("base64") } },
    }),
  );
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
  it("stages the CLI-only Linux arm64 leg beside the three updater legs", () => {
    const payload = createUnsignedPayload();

    stage(payload);

    expect(planLines(payload.root, "signing-plan.tsv")).toEqual(
      UPDATER_LEGS.map((leg) => [leg.target, leg.filename, leg.archive]),
    );
    expect(planLines(payload.root, "cli-signing-plan.tsv")).toEqual([
      [CLI_LEG.target, CLI_LEG.archive],
    ]);
    expect(fs.readdirSync(path.join(payload.root, "signing-input", CLI_LEG.target)).sort()).toEqual(
      [CLI_LEG.archive, `${CLI_LEG.archive}.sha256`, "fragment.json"].sort(),
    );
    expect(
      fs.readdirSync(path.join(payload.root, "signing-input", "darwin-universal")).sort(),
    ).toEqual(
      [
        UPDATER_LEGS[0].dmg_name,
        UPDATER_LEGS[0].filename,
        UPDATER_LEGS[0].archive,
        `${UPDATER_LEGS[0].archive}.sha256`,
        "fragment.json",
      ].sort(),
    );
  });

  it("rejects a CLI-only fragment for a target the release does not ship", () => {
    const payload = createUnsignedPayload({ cliTarget: "linux-riscv64" });

    const result = run("stage-signer-inputs.sh", payload.root, {
      EXPECTED_CANDIDATE_HASH: payload.candidateHash,
      EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
    });

    expect(result.status).not.toBe(0);
    expect(result.stdout + result.stderr).toContain(
      "Unexpected CLI-only signer target: linux-riscv64",
    );
    expect(fs.existsSync(path.join(payload.root, "signing-input", "linux-riscv64"))).toBe(false);
  });

  it("rejects a CLI-only fragment that carries a DMG", () => {
    const payload = createUnsignedPayload({ cliDmg: true });

    const result = run("stage-signer-inputs.sh", payload.root, {
      EXPECTED_CANDIDATE_HASH: payload.candidateHash,
      EXPECTED_SOURCE_COMMIT: SOURCE_COMMIT,
    });

    expect(result.status).not.toBe(0);
    expect(result.stdout + result.stderr).toContain("carries a DMG");
  });

  it("records the CLI-only leg with provenance and without an updater signature", () => {
    const payload = createUnsignedPayload();
    stage(payload);
    sign(payload.root);

    const result = record(payload);

    expect(result.stderr).toBe("");
    expect(result.status).toBe(0);
    const cliDir = path.join(payload.root, "signed-release-payload", CLI_LEG.target);
    const cliFragment = JSON.parse(fs.readFileSync(path.join(cliDir, "fragment.json"), "utf8"));
    expect(cliFragment).toEqual({
      target: CLI_LEG.target,
      cli_archive: CLI_LEG.archive,
      candidate_hash: payload.candidateHash,
      source_commit: SOURCE_COMMIT,
    });
    expect(fs.readFileSync(path.join(cliDir, "SHA256SUMS"), "utf8")).toContain(
      `  ${CLI_LEG.archive}.sig\n`,
    );
    const linuxDir = path.join(payload.root, "signed-release-payload", "linux-x86_64");
    const linuxFragment = JSON.parse(fs.readFileSync(path.join(linuxDir, "fragment.json"), "utf8"));
    expect(linuxFragment.signature).toBe(
      Buffer.from(`signature of ${UPDATER_LEGS[1].filename}`).toString("base64"),
    );
    expect(linuxFragment.artifact_sha256).toBe(
      fileHash(path.join(linuxDir, UPDATER_LEGS[1].filename)),
    );
    expect(
      fs.existsSync(path.join(payload.root, "signed-release-payload", "SHA256SUMS.minisig")),
    ).toBe(true);
  });

  it("refuses to record a CLI-only leg whose archive was not signed", () => {
    const payload = createUnsignedPayload();
    stage(payload);
    sign(payload.root, { skipCliArchive: true });

    const result = record(payload);

    expect(result.status).not.toBe(0);
    expect(fs.existsSync(path.join(payload.root, "signed-release-payload", CLI_LEG.target))).toBe(
      false,
    );
  });

  it("verifies the CLI-only leg over its archive and the release manifest alone", () => {
    const payload = createUnsignedPayload();
    stage(payload);
    sign(payload.root);
    expect(record(payload).status).toBe(0);
    const log = prepareVerifier(payload.root);

    const cliResult = verify(payload, CLI_LEG.target);
    expect(cliResult.stderr).toBe("");
    expect(cliResult.status).toBe(0);
    expect(fs.readFileSync(log, "utf8")).toBe(
      `payload/${CLI_LEG.target}/${CLI_LEG.archive}\npayload/SHA256SUMS\n`,
    );

    fs.unlinkSync(log);
    const macResult = verify(payload, "darwin-universal");
    expect(macResult.stderr).toBe("");
    expect(macResult.status).toBe(0);
    expect(fs.readFileSync(log, "utf8")).toBe(
      `payload/darwin-universal/${UPDATER_LEGS[0].filename}\n` +
        `payload/darwin-universal/${UPDATER_LEGS[0].archive}\npayload/SHA256SUMS\n`,
    );
  });
});
