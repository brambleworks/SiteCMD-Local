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

  it("rejects a CLI signed by another macOS team before notarization", () => {
    // The builder can submit a CLI signed by the wrong Developer ID team.
    const created = fixture();
    const result = created.run("build-cli.sh", { APPLE_TEAM_ID: "OTHERTEAM" });
    expect(result.status, result.stderr).not.toBe(0);
    expect(
      created.calls().some((call) => call.name === "codesign" && call.args.includes("-dv")),
    ).toBe(true);
    expect(created.calls().some((call) => call.name === "xcrun")).toBe(false);
    expect(
      fs.existsSync(path.join(created.root, "sitecmd-cli_1.5.0_darwin-universal.tar.gz")),
    ).toBe(false);
  });

  it("rejects a signed macOS archive whose team differs from its fragment", () => {
    // Valid macOS signatures can belong to a team other than the one recorded for the release.
    const created = fixture();
    expect(created.run("build-cli.sh").status).toBe(0);
    created.prepareVerification("OTHERTEAM");
    const result = created.run("verify-unix-artifacts.sh", { EXPECTED_VERSION: "1.5.0" });
    expect(result.status, result.stderr).not.toBe(0);
    expect(created.calls()).toContainEqual({
      name: "codesign",
      args: ["-dv", "--verbose=4", "cli-check/sitecmd"],
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
