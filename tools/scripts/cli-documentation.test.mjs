import { describe, it } from "vitest";
import {
  expectGuardrailFailure,
  mustMutate,
  readFixtureFile,
  writeFixtureFile,
  rules,
} from "./guardrail-test-support.mjs";

it.each(["headless_chrome", "hickory-resolver"])(
  "cli_manifests_carry_no_browser_or_dns_client (%s)",
  (dependency) => {
    // Bug: The runtime manifest can reintroduce a native scanner dependency.
    expectGuardrailFailure(
      rules.cliSurfaceFailures,
      (root) => {
        const file = "apps/desktop/src-tauri/crates/runtime/Cargo.toml";
        writeFixtureFile(
          root,
          file,
          mustMutate(
            readFixtureFile(root, file),
            "[dependencies]",
            `[dependencies]\n${dependency} = "1"`,
          ),
        );
      },
      `must not depend on ${dependency}`,
    );
  },
);

describe("CLI documentation parity", () => {
  it("fails when a dispatched command has no CLI reference entry", () => {
    expectGuardrailFailure(
      rules.cliSurfaceFailures,
      (root) => {
        const file = "apps/desktop/src-tauri/crates/cli/src/main.rs";
        writeFixtureFile(
          root,
          file,
          mustMutate(
            readFixtureFile(root, file),
            '        "audit" =>',
            '        "undocumented" => ExitCode::SUCCESS,\n        "audit" =>',
          ),
        );
      },
      "sitecmd undocumented has no CLI reference entry",
    );
  });

  it("fails when the CLI reference documents an unavailable command", () => {
    expectGuardrailFailure(
      rules.cliSurfaceFailures,
      (root) => {
        const file = "README.md";
        writeFixtureFile(
          root,
          file,
          `${readFixtureFile(root, file)}\n\`sitecmd unavailable --help\`\n`,
        );
      },
      "sitecmd unavailable is documented but not dispatched",
    );
  });
});

describe("CLI option documentation parity", () => {
  it("fails when documented rules flags are rejected by the parser", () => {
    expectGuardrailFailure(
      rules.cliSurfaceFailures,
      (root) =>
        writeFixtureFile(
          root,
          "README.md",
          `${readFixtureFile(root, "README.md")}\n\`sitecmd rules --not-a-format json\`\n`,
        ),
      "sitecmd rules documents unsupported option --not-a-format",
    );
  });

  it("fails when a rules parser option is undocumented", () => {
    expectGuardrailFailure(
      rules.cliSurfaceFailures,
      (root) =>
        writeFixtureFile(
          root,
          "README.md",
          readFixtureFile(root, "README.md").replaceAll("rules --format", "rules"),
        ),
      "sitecmd rules option --format has no README documentation",
    );
  });
});
