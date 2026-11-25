import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { expect, test } from "vitest";
import { VERSION_FILES } from "./lib/version-files.mjs";

const root = fileURLToPath(new URL("../..", import.meta.url));
const cargoRoot = fileURLToPath(new URL("../../apps/desktop/src-tauri/", import.meta.url));

test("version_carriers_are_the_cli_files", () => {
  // The release helper still tried to stamp removed desktop and MCP packages.
  expect(VERSION_FILES.map(({ file }) => file)).toEqual([
    "apps/desktop/src-tauri/crates/cli/Cargo.toml",
    "apps/desktop/src-tauri/crates/runtime/Cargo.toml",
    "apps/desktop/src-tauri/Cargo.lock",
  ]);
});

test("no_workspace_package_is_desktop_or_mcp", () => {
  // Packaging the CLI still pulled desktop and MCP dependencies into the workspace.
  const pnpm = JSON.parse(
    execFileSync("pnpm", ["ls", "--recursive", "--depth", "-1", "--json"], {
      cwd: root,
      encoding: "utf8",
    }),
  );
  const cargo = JSON.parse(
    execFileSync("cargo", ["metadata", "--no-deps", "--format-version", "1"], {
      cwd: cargoRoot,
      encoding: "utf8",
    }),
  );
  expect(
    pnpm.map(({ name }) => name),
    "pnpm members",
  ).toEqual(["sitecmd-workspace"]);
  expect(
    cargo.packages.map(({ name }) => name),
    "Cargo members",
  ).not.toContain("sitecmd");
  expect(cargo.packages.map(({ name }) => name)).toContain("sitecmd-cli");
});
