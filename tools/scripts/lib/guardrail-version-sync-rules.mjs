import { posix } from "node:path";

import { tomlFields, tomlText } from "./toml-fields.mjs";
import { isPrivateRustPath, RUST_WORKSPACE } from "./guardrail-protocol-contents-rules.mjs";
import { VERSION_FILES } from "./version-files.mjs";

const RUST_MSRV = "1.95.0";

export function versionSyncFailures(read) {
  const failures = [];
  const found = VERSION_FILES.map(({ file, read: extract }) => [file, extract(read(file))]);
  const versions = new Set(found.map(([, version]) => version));
  if (versions.size !== 1 || versions.has(undefined)) {
    failures.push(
      `SiteCMD version is out of sync across release files: ${found
        .map(([file, version]) => `${file}=${version ?? "MISSING"}`)
        .join("; ")}. Run \`pnpm release <version>\` to bump them together.`,
    );
  }

  failures.push(...rustVersionFailures(read, (member) => !isPrivateRustPath(member)));

  const nodeVersion = read(".nvmrc").trim().replace(/^v/, "");
  const rootPackage = JSON.parse(read("package.json"));
  const nodeMajor = Number.parseInt(nodeVersion.split(".")[0] ?? "", 10);
  const expectedNodeRange = `>=${nodeVersion} <${nodeMajor + 1}`;
  if (rootPackage.engines?.node !== expectedNodeRange) {
    failures.push(
      `The root Node engine must use .nvmrc as its minimum and stay within that major: expected ${expectedNodeRange}; found ${rootPackage.engines?.node ?? "MISSING"}.`,
    );
  }
  const runtime = rootPackage.devEngines?.runtime;
  if (
    runtime?.name !== "node" ||
    runtime?.version !== expectedNodeRange ||
    runtime?.onFail !== "error"
  ) {
    failures.push(
      "The root devEngines.runtime must enforce the same Node range as engines.node with onFail set to error.",
    );
  }
  if (!/^engineStrict:\s*true\s*$/m.test(read("pnpm-workspace.yaml"))) {
    failures.push(
      "pnpm-workspace.yaml must keep engineStrict enabled so incompatible dependency engines fail installation.",
    );
  }

  return failures;
}

const rootManifest = `${RUST_WORKSPACE}/Cargo.toml`;

function workspaceMemberEntries(read) {
  const members = tomlFields(read(rootManifest)).find(
    ({ path }) => path.length === 2 && path[0] === "workspace" && path[1] === "members",
  )?.value;
  return Array.isArray(members) ? members.filter((token) => token !== ",").map(tomlText) : null;
}

export function publicRustMemberRoots(read) {
  return (workspaceMemberEntries(read) ?? [])
    .filter((member) => !/[*?[]/.test(member))
    .map((member) => posix.join(RUST_WORKSPACE, member))
    .filter((member) => !isPrivateRustPath(member));
}

export function rustVersionFailures(read, includeMember = () => true) {
  const failures = [];
  const members = workspaceMemberEntries(read);
  const rustManifests = new Set();
  if (!Array.isArray(members)) {
    failures.push(`${rootManifest} must list its [workspace] members for the Rust version check.`);
  } else {
    for (const member of members) {
      if (/[*?[]/.test(member)) {
        failures.push(
          `${rootManifest} member ${member} is a glob; list each member for the Rust version check.`,
        );
        continue;
      }
      const memberRoot = posix.join(RUST_WORKSPACE, member);
      if (includeMember(memberRoot)) rustManifests.add(posix.join(memberRoot, "Cargo.toml"));
    }
  }
  const rustVersions = Array.from(rustManifests, (file) => [
    file,
    tomlFields(read(file)).find(
      ({ path }) => path.length === 2 && path[0] === "package" && path[1] === "rust-version",
    )?.value,
  ]);
  if (rustVersions.some(([, version]) => version !== RUST_MSRV)) {
    failures.push(
      `Rust MSRV is out of sync with the tested ${RUST_MSRV} floor: ${rustVersions
        .map(([file, version]) => `${file}=${version ?? "MISSING"}`)
        .join("; ")}.`,
    );
  }

  return failures;
}
