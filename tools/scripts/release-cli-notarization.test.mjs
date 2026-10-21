import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { releaseCliFixture } from "./lib/release-cli-test-fixture.mjs";

const fixtures = [];
const fixture = (options) => {
  const created = releaseCliFixture(options);
  fixtures.push(created);
  return created;
};

afterEach(() => {
  for (const created of fixtures.splice(0)) created.clean();
});

describe("CLI release notarization", () => {
  it("supplies notary credentials and retains evidence even when the CLI build fails", () => {
    const workflow = fs.readFileSync(
      new URL("../../.github/workflows/release.yml", import.meta.url),
      "utf8",
    );
    const step = (name) => {
      const start = workflow.indexOf(`      - name: ${name}\n`);
      expect(start, name).toBeGreaterThan(-1);
      return workflow.slice(start, workflow.indexOf("\n      - ", start + 1));
    };
    const build = step("Build CLI (headless scanner)");
    expect(build).toContain("APPLE_API_KEY_ID:");
    expect(build).toContain("secrets.APPLE_API_KEY_ID");
    expect(build).toContain("APPLE_API_ISSUER:");
    expect(build).toContain("secrets.APPLE_API_ISSUER");
    const evidence = step("Preserve CLI notarization evidence");
    expect(evidence).toContain("always()");
    expect(evidence).toContain("startsWith(matrix.target, 'darwin')");
    expect(evidence).toContain("uses: actions/upload-artifact@");
    for (const name of ["submission.json", "submission-id.txt", "notary-log.json"]) {
      expect(evidence).toContain(`cli-notarization/${name}`);
    }
    expect(evidence).not.toContain("asc_api_key.p8");
  });

  it("submits the signed universal bytes and packages them only after acceptance", () => {
    const created = fixture();
    const result = created.run("build-cli.sh");
    expect(result.status, result.stderr).toBe(0);
    const calls = created.calls();
    const submit = calls.find((call) => call.name === "xcrun" && call.args[1] === "submit");
    expect(submit, "the CLI must be submitted to Apple's notary service").toBeDefined();
    expect(submit.args).toEqual([
      "notarytool",
      "submit",
      expect.stringMatching(/\.zip$/),
      "--key",
      path.join(created.runnerTemp, "asc_api_key.p8"),
      "--key-id",
      "fixture-key-id",
      "--issuer",
      "fixture-issuer",
      "--wait",
      "--output-format",
      "json",
    ]);
    expect(calls.findIndex((call) => call.name === "codesign")).toBeLessThan(
      calls.findIndex((call) => call.name === "ditto"),
    );
    expect(calls.findIndex((call) => call.name === "ditto")).toBeLessThan(calls.indexOf(submit));
    const submitted = execFileSync("unzip", ["-p", submit.args[2], "sitecmd"]);
    const packaged = execFileSync("tar", [
      "-xOf",
      path.join(created.root, "sitecmd-cli_1.5.0_darwin-universal.tar.gz"),
      "sitecmd",
    ]);
    expect(submitted.toString()).toContain("# Signed fixture");
    expect(packaged.equals(submitted)).toBe(true);
    const output = path.join(created.runnerTemp, "cli-notarization");
    expect(fs.readFileSync(path.join(output, "submission-id.txt"), "utf8")).toBe(
      "fixture-submission\n",
    );
    expect(JSON.parse(fs.readFileSync(path.join(output, "notary-log.json"), "utf8"))).toEqual({
      jobId: "fixture-submission",
      status: "Accepted",
    });
    expect(calls.some((call) => call.args.includes("stapler"))).toBe(false);
  });

  it.each([
    ["Invalid", { status: "Invalid" }],
    ["In Progress", { status: "In Progress" }],
    ["missing status", { status: null }],
    ["missing submission id", { id: null }],
    ["transport failure", { submitExit: 1 }],
    ["unavailable notary log", { logFailure: true }],
  ])("refuses to package a CLI with %s", (_name, options) => {
    const created = fixture(options);
    const result = created.run("build-cli.sh");
    expect(result.status, result.stderr).not.toBe(0);
    expect(
      fs.existsSync(path.join(created.root, "sitecmd-cli_1.5.0_darwin-universal.tar.gz")),
    ).toBe(false);
  });

  it("assesses the standalone CLI's online notarization beside its signature", () => {
    const created = fixture();
    expect(created.run("build-cli.sh").status).toBe(0);
    created.prepareVerification();
    const result = created.run("verify-unix-artifacts.sh", { EXPECTED_VERSION: "1.5.0" });
    expect(result.status, result.stderr).toBe(0);
    const calls = created.calls().filter((call) => call.name === "codesign");
    expect(calls).toContainEqual({
      name: "codesign",
      args: ["-vvvv", "-R=notarized", "--check-notarization", "cli-check/sitecmd"],
    });
  });

  it("fails artifact verification when the CLI's online notarization is refused", () => {
    const created = fixture({ assessmentFailure: true });
    expect(created.run("build-cli.sh").status).toBe(0);
    created.prepareVerification();
    const result = created.run("verify-unix-artifacts.sh", { EXPECTED_VERSION: "1.5.0" });
    expect(result.status, result.stderr).not.toBe(0);
  });
});
