import fs from "node:fs";
import path from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { VERSION_FILES } from "./lib/version-files.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const SCRIPT_DIR = ".github/scripts/release";
const SCRIPT_STEPS = new Map([
  ["build-candidate-manifest.sh", "Build release candidate manifest"],
  ["build-cli.sh", "Build CLI (headless scanner)"],
  ["sign-cli.sh", "Sign and package the CLI"],
  ["publish-npm-packages.sh", "Publish the verified binaries as @sitecmd/cli"],
  ["record-signed-payload.sh", "Record signed payload provenance without secrets"],
  ["stage-signer-inputs.sh", "Validate and stage signer inputs without secrets"],
  ["verify-signed-payload.sh", "Verify payload hashes, provenance, and updater signature"],
  ["verify-unix-artifacts.sh", "Verify Unix CLI and macOS code signature"],
]);

const read = (relativePath) => fs.readFileSync(path.join(ROOT, relativePath), "utf8");
const hasPowerShell =
  spawnSync("pwsh", ["-NoProfile", "-NonInteractive", "-Command", "exit 0"]).status === 0;

describe("release workflow scripts", () => {
  it("keeps platform signing credentials off the runner that executes the CLI", () => {
    const workflow = read(".github/workflows/release.yml");
    const build = workflow.split("  build:\n")[1].split(/\n {2}[a-z][\w-]*:\n/)[0];
    expect(build).not.toMatch(/release-signing|secrets\.(?:APPLE|AZURE|KEYCHAIN)/);
    expect(read(`${SCRIPT_DIR}/build-cli.sh`)).toContain("--version");
    const signer = workflow.split("  sign-platforms:\n")[1].split(/\n {2}[a-z][\w-]*:\n/)[0];
    expect(signer).toContain("digest-mismatch: error");
    expect(signer).toContain("name: release-signing");
    expect(read(`${SCRIPT_DIR}/sign-cli.sh`)).not.toMatch(/--version|cargo build/);
  });

  it("matches the Azure probe after leaf renewal by using the same signer identity check in both jobs", () => {
    const workflow = read(".github/workflows/release.yml");
    const probe = workflow
      .split("      - name: Verify Azure signing")[1]
      .split("\n      - name:")[0];
    const verifier = workflow
      .split("      - name: Verify Windows CLI and Authenticode signature")[1]
      .split("\n      - name:")[0];

    expect(`${probe}\n${verifier}`).not.toContain("SignerCertificate.Thumbprint");
    expect(probe).toContain("Get-WindowsSignerIdentity");
    expect(verifier).toContain("Get-WindowsSignerIdentity -Path $cli");
    expect(verifier).toContain("$cliSigner -cne $fragment.signer_identity");
  });

  it("signs a probe copy of the downloaded CLI after checking its digest", () => {
    const signer = read(".github/workflows/release.yml")
      .split("  sign-platforms:\n")[1]
      .split(/\n {2}[a-z][\w-]*:\n/)[0];

    expect(signer).toMatch(
      /digest-mismatch: error[\s\S]*?cp "\$RUNNER_TEMP\/cli-dist\/sitecmd\.exe" sign-probe\.exe/,
    );
  });

  it("rejects Windows catalog signatures in the shared signer check", () => {
    expect(read(`${SCRIPT_DIR}/windows-signer-identity.ps1`)).toContain(
      '$signature.SignatureType -ne "Authenticode"',
    );
  });

  it("matches renewed certificates across issuing CAs and distinguishes profiles by EKU", () => {
    const helper = read(`${SCRIPT_DIR}/windows-signer-identity.ps1`);

    expect(helper).toContain('return "${subject}:$($profileEku[0])"');
    expect(helper).not.toContain("X509Chain");
  });

  it("requires the Public Trust and code signing EKUs and one profile EKU", () => {
    const helper = read(`${SCRIPT_DIR}/windows-signer-identity.ps1`);

    expect(helper).toContain('$publicTrustEku = "1.3.6.1.4.1.311.97.1.0"');
    expect(helper).toContain("$ekus -notcontains $publicTrustEku");
    expect(helper).toContain('$ekus -notcontains "1.3.6.1.5.5.7.3.3"');
    expect(helper).toContain("$profileEku.Count -ne 1");
  });

  it.skipIf(!process.env.CI && !hasPowerShell)(
    "enforces the embedded signature and Azure profile identity across certificate renewals",
    () => {
      expect(
        hasPowerShell,
        "PowerShell (pwsh) is required for the Windows signer tests in CI",
      ).toBe(true);
      execFileSync("pwsh", [
        "-NoProfile",
        "-NonInteractive",
        "-File",
        path.join(ROOT, "tools/scripts/testdata/windows-signer-renewal.ps1"),
      ]);
    },
    // Starting pwsh, three RSA keys and ten certificates can outrun the default on a busy runner.
    30_000,
  );

  it.each(["unsigned-platform-", "signed-release-payload"])(
    "retains %s artifacts for a week of approval windows",
    (name) => {
      const release = read(".github/workflows/release.yml");
      const artifact = release.split(`name: ${name}`)[1].split(/\n\s*-/)[0];
      expect(artifact).toContain("retention-days: 7");
    },
  );

  it("builds the runtime test-support API in CI", () => {
    expect(read(".github/workflows/ci.yml")).toContain(
      "cargo check --locked -p sitecmd-runtime --features test-support",
    );
  });

  it("serializes releases across all tag names", () => {
    expect(read(".github/workflows/release.yml")).toMatch(
      /\nconcurrency:\n {2}group: release\n {2}cancel-in-progress: false\n/,
    );
  });

  it("keys pull-request concurrency by PR number so forks cannot collide", () => {
    const ci = read(".github/workflows/ci.yml").split("concurrency:\n")[1].split("\n\n")[0];
    expect(ci).toContain("github.event.pull_request.number || github.run_id");
    expect(ci).not.toContain("github.head_ref");
  });

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

  it("runs every CLI target through build, signing, verification, and publication", () => {
    // A CLI platform can drop out of one stage of the release.
    const workflow = read(".github/workflows/release.yml");
    const job = (name, next) =>
      workflow.slice(workflow.indexOf(`\n  ${name}:`), workflow.indexOf(`\n  ${next}:`));
    const build = job("build", "sign-platforms");
    const signing = job("sign-platforms", "sign-updaters");
    const verify = job("verify-release", "publish-release");
    const publish = job("publish-release", "publish-npm");
    const stage = read(`${SCRIPT_DIR}/stage-signer-inputs.sh`);

    for (const target of ["darwin-universal", "linux-x86_64", "linux-aarch64", "windows-x86_64"]) {
      expect(build).toContain(`target: ${target}\n`);
      expect(signing).toContain(`target: ${target}\n`);
      expect(verify).toContain(`target: ${target}\n`);
      expect(stage).toContain(target);
      expect(publish).toContain(target);
    }
    expect(build).toMatch(
      /- os: ubuntu-22\.04-arm\n\s+target: linux-aarch64\n\s+rust_target: aarch64-unknown-linux-gnu\n/,
    );
    expect(verify).toMatch(/- os: ubuntu-22\.04-arm\n\s+target: linux-aarch64\n/);
    expect(stage).toContain('test "$count" -eq 4');
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
