#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import path from "node:path";

const EXPECTED_VERSION = "v1.7.12";
const executable = process.platform === "win32" ? "actionlint.exe" : "actionlint";
const candidates = [executable];
const goPath = spawnSync("go", ["env", "GOPATH"], { encoding: "utf8" });
if (goPath.status === 0 && goPath.stdout.trim()) {
  candidates.push(path.join(goPath.stdout.trim(), "bin", executable));
}

let actionlint;
for (const candidate of candidates) {
  const version = spawnSync(candidate, ["-version"], { encoding: "utf8" });
  if (version.error?.code === "ENOENT") continue;
  if (version.status !== 0) {
    process.stderr.write(version.stderr || `Could not run ${candidate}.\n`);
    process.exit(version.status ?? 1);
  }
  // `go install` builds print `v1.7.12`; Homebrew's print `1.7.12`.
  const printed = version.stdout.trim().split(/\s+/)[0];
  const actualVersion = printed && `v${printed.replace(/^v/, "")}`;
  if (actualVersion !== EXPECTED_VERSION) {
    process.stderr.write(
      `actionlint ${EXPECTED_VERSION} is required, found ${actualVersion || "unknown"}.\n` +
        `Install it with: go install github.com/rhysd/actionlint/cmd/actionlint@${EXPECTED_VERSION}\n`,
    );
    process.exit(1);
  }
  actionlint = candidate;
  break;
}

if (!actionlint) {
  process.stderr.write(
    `actionlint ${EXPECTED_VERSION} is required. Install it with:\n` +
      `  go install github.com/rhysd/actionlint/cmd/actionlint@${EXPECTED_VERSION}\n`,
  );
  process.exit(1);
}

const result = spawnSync(actionlint, process.argv.slice(2), {
  cwd: process.cwd(),
  stdio: "inherit",
});
if (result.error) {
  process.stderr.write(`Could not run actionlint: ${result.error.message}\n`);
  process.exit(1);
}
process.exit(result.status ?? 1);
