import { expect, it } from "vitest";
import { packageCommand } from "./lib/ci-step-pins.mjs";
import { SCAN_TYPES, cliDependencyFailures } from "./lib/guardrail-cli-surface-rules.mjs";
import { usesGuardedMetadataReads } from "./lib/guardrail-project-metadata-rules.mjs";
import { storageGateFailures } from "./lib/guardrail-protocol-contents-rules.mjs";
import { connectedSpecFailures } from "./lib/guardrail-public-face-rules.mjs";
import { rustVersionFailures } from "./lib/guardrail-version-sync-rules.mjs";

it("keeps package manager flags out of the script name", () => {
  // Bug: pnpm's directory flag can hide the command that needs a toolchain.
  expect(packageCommand(["pnpm", "--dir", ".", "run", "check", "--locked"])).toEqual({
    script: "check",
    scriptArgs: ["--locked"],
  });
});

it("distinguishes internal scan profiles from public check categories", () => {
  // Bug: Internal profiles can drift into the product category vocabulary.
  expect([...SCAN_TYPES]).toEqual(["health", "security", "accessibility", "polish"]);
});

it("checks package aliases as well as direct CLI dependency names", () => {
  // Bug: A Cargo alias can hide a browser client from the CLI dependency guard.
  const manifest = '[dependencies]\nbrowser = { package = "headless_chrome", version = "1" }';
  expect(
    cliDependencyFailures(
      () => manifest,
      () => true,
    ).join("\n"),
  ).toContain("must not depend on headless_chrome");
});

it("allows guarded metadata calls and rejects raw file reads", () => {
  // Bug: Project metadata can bypass the bounded reader.
  expect(usesGuardedMetadataReads("read_bounded_text_under_root(root, relative, max)")).toBe(true);
  expect(usesGuardedMetadataReads("fs::read_to_string(path)")).toBe(false);
});

it("rejects access to protocol storage from a runtime file", () => {
  // Bug: A runtime caller can bypass the reviewed storage boundary.
  const source = "use sitecmd_protocol::storable as gate;";
  const file = "apps/desktop/src-tauri/src/connected_service.rs";
  expect(storageGateFailures(() => source, [file])).toEqual([
    `${file} - only the engine may access the protocol storage gate.`,
  ]);
});

it("requires connected specifications to state the applicable contract", () => {
  // Bug: A public specification can defer the protocol rules to a private record.
  const file = "docs/engineering/connected-service/example.md";
  expect(connectedSpecFailures(file, "Follow the commercial terms spec.").join("\n")).toContain(
    "defers to a private record",
  );
  expect(connectedSpecFailures(file, "The rules are stated here.")).toEqual([]);
});

it("rejects a public workspace member whose MSRV drifts", () => {
  // Bug: A package can require a Rust compiler newer than the CI compatibility job.
  const read = (file) =>
    file.endsWith("crates/protocol/Cargo.toml")
      ? '[package]\nrust-version = "1.97.0"'
      : '[workspace]\nmembers = ["crates/protocol"]';
  expect(rustVersionFailures(read).join("\n")).toContain("crates/protocol/Cargo.toml=1.97.0");
});
