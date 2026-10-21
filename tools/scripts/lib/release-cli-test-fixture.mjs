import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../../..", import.meta.url));
const COMMAND_DOUBLE = `#!/usr/bin/env node
const fs = require("node:fs");
const path = require("node:path");
const { execFileSync } = require("node:child_process");
const root = path.dirname(path.dirname(process.argv[1]));
const name = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const config = JSON.parse(fs.readFileSync(path.join(root, "fixture.json"), "utf8"));
fs.appendFileSync(path.join(root, "calls.jsonl"), JSON.stringify({ name, args }) + "\\n");
const value = (flag) => args[args.indexOf(flag) + 1];
if (name === "cargo" && args[0] === "build") {
  const binary = path.join(root, "apps/desktop/src-tauri/target", value("--target"), "release/sitecmd_cli");
  fs.mkdirSync(path.dirname(binary), { recursive: true });
  fs.writeFileSync(binary, "#!/bin/sh\\nprintf 'sitecmd 1.5.0\\\\n'\\n", { mode: 0o755 });
} else if (name === "cargo" && args[0] === "license") {
  fs.writeFileSync(value("--output"), "Fixture license\\n");
} else if (name === "lipo") {
  fs.copyFileSync(args[1], value("-output"));
} else if (name === "codesign") {
  if (args.includes("--sign")) fs.appendFileSync(args.at(-1), "# Signed fixture\\n");
  if (args.includes("--check-notarization") && config.assessmentFailure) process.exit(1);
  if (args.includes("-dv")) console.error("TeamIdentifier=FIXTURETEAM");
} else if (name === "ditto") {
  execFileSync("zip", ["-q", "-j", args.at(-1), args.at(-2)]);
} else if (name === "xcrun" && args[0] === "notarytool") {
  if (args[1] === "submit") {
    console.log(JSON.stringify({ id: config.id, status: config.status }));
    process.exit(config.submitExit || 0);
  } else if (args[1] === "log") {
    if (config.logFailure) process.exit(1);
    fs.writeFileSync(args.at(-1), JSON.stringify({ jobId: config.id, status: config.status }));
  } else process.exit(91);
} else if (!["spctl", "xcrun"].includes(name)) process.exit(92);
`;

export function releaseCliFixture(overrides = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd cli release "));
  const bin = path.join(root, "bin");
  const runnerTemp = path.join(root, "runner temp");
  const src = path.join(root, "apps/desktop/src-tauri");
  fs.mkdirSync(bin);
  fs.mkdirSync(runnerTemp);
  fs.mkdirSync(src, { recursive: true });
  fs.writeFileSync(path.join(runnerTemp, "asc_api_key.p8"), "Fixture API key\n");
  fs.writeFileSync(
    path.join(root, "fixture.json"),
    JSON.stringify({ id: "fixture-submission", status: "Accepted", ...overrides }),
  );
  for (const name of ["cargo", "lipo", "codesign", "ditto", "xcrun", "spctl"]) {
    fs.writeFileSync(path.join(bin, name), COMMAND_DOUBLE, { mode: 0o755 });
  }
  for (const name of [
    "LICENSE",
    "NOTICE",
    "THIRD_PARTY_NOTICES",
    "THIRD_PARTY_DEPENDENCIES.json",
    "THIRD_PARTY_LICENSES.txt",
  ]) {
    fs.writeFileSync(path.join(root, name), "Fixture legal notice\n");
  }
  const env = {
    ...process.env,
    PATH: `${bin}${path.delimiter}${process.env.PATH}`,
    GITHUB_WORKSPACE: root,
    GITHUB_REF_NAME: "v1.5.0",
    GITHUB_OUTPUT: path.join(root, "outputs.txt"),
    RUNNER_TEMP: runnerTemp,
    TARGET: "darwin-universal",
    RUST_TARGET: "universal-apple-darwin",
    APPLE_CERTIFICATE: "fixture-certificate",
    APPLE_SIGNING_IDENTITY: "fixture-identity",
    APPLE_API_KEY_ID: "fixture-key-id",
    APPLE_API_ISSUER: "fixture-issuer",
  };
  return {
    root,
    runnerTemp,
    env,
    run(script, extraEnv = {}) {
      return spawnSync("bash", [path.join(ROOT, ".github/scripts/release", script)], {
        cwd: root,
        env: { ...env, ...extraEnv },
        encoding: "utf8",
        timeout: 15_000,
      });
    },
    calls() {
      return fs
        .readFileSync(path.join(root, "calls.jsonl"), "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line));
    },
    prepareVerification() {
      const payload = path.join(root, "payload/darwin-universal");
      const appRoot = path.join(root, "app-fixture");
      fs.mkdirSync(payload, { recursive: true });
      fs.mkdirSync(path.join(appRoot, "SiteCMD.app"), { recursive: true });
      fs.writeFileSync(path.join(appRoot, "SiteCMD.app/fixture.txt"), "Fixture app\n");
      const archive = "sitecmd-cli_1.5.0_darwin-universal.tar.gz";
      fs.copyFileSync(path.join(root, archive), path.join(payload, archive));
      fs.writeFileSync(path.join(payload, "SiteCMD.dmg"), "Fixture DMG\n");
      execFileSync("tar", [
        "-czf",
        path.join(payload, "SiteCMD.app.tar.gz"),
        "-C",
        appRoot,
        "SiteCMD.app",
      ]);
      fs.writeFileSync(
        path.join(payload, "fragment.json"),
        JSON.stringify({
          cli_archive: archive,
          filename: "SiteCMD.app.tar.gz",
          dmg_name: "SiteCMD.dmg",
        }),
      );
    },
    clean() {
      fs.rmSync(root, { recursive: true, force: true });
    },
  };
}
