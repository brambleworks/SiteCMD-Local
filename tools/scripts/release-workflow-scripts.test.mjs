import fs from "node:fs";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { VERSION_FILES } from "./lib/version-files.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCRIPT_DIR = ".github/scripts/release";
const SCRIPT_STEPS = new Map([
  ["build-candidate-manifest.sh", "Build release candidate manifest"],
  ["build-cli.sh", "Build CLI (headless scanner)"],
  ["build-macos-dmg.sh", "Restyle macOS DMG (deterministic, Finder-free)"],
  ["build-tauri-app.sh", "Build Tauri app with ephemeral updater key"],
  ["locate-updater-bundle.sh", "Locate updater bundle and signature"],
  ["publish-npm-packages.sh", "Publish the verified binaries as @sitecmd/cli"],
  ["record-signed-payload.sh", "Record signed payload provenance without secrets"],
  ["stage-signer-inputs.sh", "Validate and stage signer inputs without secrets"],
  ["verify-signed-payload.sh", "Verify payload hashes, provenance, and updater signature"],
  ["verify-unix-artifacts.sh", "Verify Unix CLI and macOS platform signatures"],
]);

const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");

describe("release workflow scripts", () => {
  it("stages every version carrier named by the release helper", () => {
    const runbook = read("docs/operations/releasing.md");
    const stageBlock = runbook.match(/git add ([\s\S]*?)\ngit commit/)?.[1];

    expect(stageBlock).toBeDefined();

    for (const { file } of VERSION_FILES) {
      expect(stageBlock).toContain(file);
    }
    expect(runbook).not.toMatch(/all (?:four|five) (?:source )?version files/i);
  });

  it("keeps every extracted script wired to exactly one named workflow step", () => {
    const workflow = read(".github/workflows/release.yml");
    const scripts = fs
      .readdirSync(path.join(ROOT, SCRIPT_DIR))
      .filter((name) => name.endsWith(".sh"))
      .sort();

    expect(scripts).toEqual([...SCRIPT_STEPS.keys()].sort());
    for (const [script, step] of SCRIPT_STEPS) {
      expect(workflow).toContain(`- name: ${step}`);
      expect(workflow.split(`run: bash ${SCRIPT_DIR}/${script}`).length - 1).toBe(1);
    }
    expect(workflow).not.toMatch(/^\s+node-version:/m);
  });

  it("includes helpers in jobs that use sparse checkout", () => {
    const workflow = read(".github/workflows/release.yml");
    const signerJob = workflow.slice(
      workflow.indexOf("  sign-updaters:"),
      workflow.indexOf("  verify-release:"),
    );
    const verifierJob = workflow.slice(
      workflow.indexOf("  verify-release:"),
      workflow.indexOf("  publish-release:"),
    );

    expect(signerJob).toContain(`            ${SCRIPT_DIR}`);
    expect(verifierJob).toContain(`            ${SCRIPT_DIR}`);
  });

  it("pins Node before the candidate helper executes JavaScript", () => {
    const workflow = read(".github/workflows/release.yml");
    const candidateJob = workflow.slice(
      workflow.indexOf("  prepare-candidate:"),
      workflow.indexOf("  build:"),
    );

    expect(candidateJob).toContain("uses: actions/setup-node@");
    expect(candidateJob).toContain("node-version-file: .nvmrc");
    expect(candidateJob.indexOf("uses: actions/setup-node@")).toBeLessThan(
      candidateJob.indexOf("run: bash .github/scripts/release/build-candidate-manifest.sh"),
    );
  });

  it("runs the Linux arm64 leg as CLI-only through every release stage", () => {
    const workflow = read(".github/workflows/release.yml");
    const job = (name, next) =>
      workflow.slice(workflow.indexOf(`\n  ${name}:`), workflow.indexOf(`\n  ${next}:`));
    const buildJob = job("build", "sign-updaters");
    const verifyJob = job("verify-release", "publish-release");
    const publishJob = job("publish-release", "publish-npm");

    expect(buildJob).toMatch(
      /- os: ubuntu-22\.04-arm\n\s+target: linux-aarch64\n\s+rust_target: aarch64-unknown-linux-gnu\n\s+rust_toolchain_targets: aarch64-unknown-linux-gnu\n\s+cli_only: true\n/,
    );
    expect(buildJob.match(/cli_only: false/g)).toHaveLength(3);
    for (const step of [
      "pnpm install",
      "Build Tauri app with ephemeral updater key",
      "Verify signing key not embedded in artifacts",
      "Locate updater bundle and signature",
    ]) {
      const start = buildJob.indexOf(`- name: ${step}\n`);
      expect(start, step).toBeGreaterThan(-1);
      const body = buildJob.slice(start, buildJob.indexOf("\n      - ", start + 1));
      expect(body, step).toContain("if: ${{ !matrix.cli_only }}");
    }
    expect(buildJob).toContain('if $filename != "" then {filename: $filename}');
    expect(verifyJob).toMatch(/- os: ubuntu-22\.04-arm\n\s+target: linux-aarch64\n/);
    expect(publishJob).toContain("linux-aarch64) ;;");
    expect(publishJob).toContain('test "$cli_count" -eq 1');
    expect(read(`${SCRIPT_DIR}/stage-signer-inputs.sh`)).toContain("linux-aarch64) ;;");
    expect(read(`${SCRIPT_DIR}/publish-npm-packages.sh`)).toContain(
      "stage_platform cli-linux-arm64 linux-aarch64 sitecmd",
    );
  });

  it("parses every script with Bash before a release can use it", () => {
    for (const script of SCRIPT_STEPS.keys()) {
      expect(() =>
        execFileSync("bash", ["-n", path.join(ROOT, SCRIPT_DIR, script)], {
          stdio: "pipe",
        }),
      ).not.toThrow();
    }
  });

  it("keeps GitHub expressions and platform line endings out of shell code", () => {
    for (const script of SCRIPT_STEPS.keys()) {
      const source = read(`${SCRIPT_DIR}/${script}`);
      expect(source).toMatch(/^set -[^\n]*\n/);
      expect(source).not.toContain("${{");
      expect(source).not.toContain("\r");
    }
  });
});
