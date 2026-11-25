// Bug: npm packages can advertise Apache-2.0 for binaries that embed the separately licensed module.
import { expect, it } from "vitest";
import { exportedTree, realRead } from "./guardrail-test-support.mjs";
import { npmCliPackageFailures } from "./lib/guardrail-npm-cli-rules.mjs";

const packages = [
  "cli",
  "cli-darwin-universal",
  "cli-linux-arm64",
  "cli-linux-x64",
  "cli-win32-x64",
];

it.each(packages)("npm_license_points_at_license (%s)", (name) => {
  const path = `packaging/npm/${name}/package.json`;
  expect(JSON.parse(realRead(path)).license).toBe("SEE LICENSE IN LICENSE");
});

it.each(packages)("rejects an Apache-only npm license (%s)", (name) => {
  const path = `packaging/npm/${name}/package.json`;
  const read = (file) => {
    const source = realRead(file);
    return file === path
      ? JSON.stringify({ ...JSON.parse(source), license: "Apache-2.0" })
      : source;
  };
  expect(npmCliPackageFailures(read, { releaseWorkflow: !exportedTree })).toContain(
    `${path} license must be SEE LICENSE IN LICENSE`,
  );
});
