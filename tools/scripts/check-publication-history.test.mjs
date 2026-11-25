import { execFileSync, spawnSync } from "node:child_process";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { runInNewContext } from "node:vm";
import { afterEach, describe, expect, it } from "vitest";
import { readWorkflow } from "./lib/guardrail-workflow-yaml.mjs";

import {
  candidateHistoryShapeFailures,
  publicationHistoryPathFailures,
} from "./lib/publication-history-rules.mjs";

describe("publicationHistoryPathFailures", () => {
  it("accepts history containing only the public client applications", () => {
    expect(
      publicationHistoryPathFailures([
        "README.md",
        "apps/desktop/src/main.tsx",
        "apps/mcp-server/src/index.ts",
      ]),
    ).toEqual([]);
  });

  it("rejects private strategy records even after deletion", () => {
    expect(
      publicationHistoryPathFailures([
        "docs/engineering/publication-decision.md",
        "docs/engineering/connected-service/commercial-terms-spec.md",
      ]).join("\n"),
    ).toContain("private strategy record");
  });

  it("rejects app trees that do not belong in the public client repository", () => {
    const failures = publicationHistoryPathFailures([
      "apps/sitecmd-telemetry/src/index.ts",
      "apps/sitecmd-telemetry/package.json",
      "apps/sitecmd.com/src/pages/index.astro",
    ]);
    expect(failures).toEqual([
      "public history contains a private/non-client app tree: apps/sitecmd-telemetry/",
      "public history contains a private/non-client app tree: apps/sitecmd.com/",
    ]);
  });
});

describe("candidateHistoryShapeFailures", () => {
  it("accepts one parentless commit", () => {
    expect(candidateHistoryShapeFailures("1", "0123456789abcdef")).toEqual([]);
  });

  it("rejects inherited commits and a parented tip", () => {
    expect(candidateHistoryShapeFailures("42", "tip parent").join("\n")).toContain(
      "exactly one commit",
    );
    expect(candidateHistoryShapeFailures("42", "tip parent").join("\n")).toContain(
      "must have no parent",
    );
  });
});

const publicUrl = "ssh://git@github.com/brambleworks/SiteCMD-Local.git";
const privateRepository = ["brambleworks", "SiteCMD-Engine"].join("/");
const branch = "refs/heads/main";
const absent = "0".repeat(40);
const workspace = "apps/desktop/src-tauri";
const privatePath = [workspace, "crates", "engine", "src", "lib.rs"].join("/");
const engineCargoName = ["sitecmd", "engine"].join("-");
const engineRustName = ["sitecmd", "engine"].join("_");
const roots = [];
const gitEnv = {
  ...process.env,
  GIT_ALLOW_PROTOCOL: "file:ssh",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_NOSYSTEM: "1",
};
const pathspecVars = [
  "GIT_LITERAL_PATHSPECS",
  "GIT_GLOB_PATHSPECS",
  "GIT_NOGLOB_PATHSPECS",
  "GIT_ICASE_PATHSPECS",
];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function git(root, ...args) {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", env: gitEnv }).trim();
}

function repository() {
  const root = mkdtempSync(join(tmpdir(), "sitecmd-public-tree-"));
  roots.push(root);
  git(root, "init", "--quiet", "--initial-branch=main", "--object-format=sha1");
  git(root, "config", "user.name", "SiteCMD");
  git(root, "config", "user.email", "sitecmd@example.com");
  git(root, "config", "commit.gpgSign", "false");
  const bare = join(root, ".git", "public.git");
  git(root, "init", "--quiet", "--bare", "--initial-branch=main", bare);
  return root;
}

function localSshEnv(root, bare = join(root, ".git", "public.git")) {
  const shim = join(root, ".git", "local-ssh");
  writeFileSync(
    shim,
    `#!/bin/sh
for arg do service=$arg; done
printf '%s\n' "$service" >> "$SITECMD_TEST_SSH_LOG"
for var in ${pathspecVars.join(" ")}; do
  if printenv "$var" >/dev/null; then printf '%s\n' "$var" >> "$SITECMD_TEST_SSH_LOG"; fi
done
case "$service" in
  "git-upload-pack "*) exec git upload-pack "$SITECMD_TEST_SSH_REPO" ;;
  "git-receive-pack "*) exec git receive-pack "$SITECMD_TEST_SSH_REPO" ;;
  *) exit 1 ;;
esac
`,
  );
  return {
    ...gitEnv,
    GIT_SSH_COMMAND: 'sh "$SITECMD_TEST_SSH_SHIM"',
    GIT_SSH_VARIANT: "ssh",
    SITECMD_TEST_SSH_LOG: join(root, ".git", "local-ssh.log"),
    SITECMD_TEST_SSH_REPO: bare,
    SITECMD_TEST_SSH_SHIM: shim,
  };
}

function rewriteLookup(root, url, bare = join(root, ".git", "public.git")) {
  git(root, "config", "--add", `url.${pathToFileURL(bare).href}.insteadOf`, url);
}

function seedBare(bare, source, commit, ref = branch) {
  git(bare, "fetch", "--quiet", pathToFileURL(source).href, `${commit}:${ref}`);
}

function commitFile(root, file, contents) {
  if (contents === undefined) {
    rmSync(join(root, file));
  } else {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), contents);
  }
  git(root, "add", "--all");
  git(root, "commit", "--quiet", "-m", "Update fixture");
  return git(root, "rev-parse", "HEAD");
}

const guardFiles = [
  "tools/scripts/check-publication-history.mjs",
  "tools/scripts/lib/publication-history-rules.mjs",
  "tools/scripts/lib/toml-fields.mjs",
];
const selector = "tools/scripts/run-public-tree-check.mjs";

function installCheck(root) {
  for (const file of [...guardFiles, selector]) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    copyFileSync(new URL(`../../${file}`, import.meta.url), join(root, file));
  }
}

function runCheck(root, args, input, env = localSshEnv(root)) {
  installCheck(root);
  return spawnSync(process.execPath, [guardFiles[0], ...args], {
    cwd: root,
    input,
    encoding: "utf8",
    env,
  });
}

function prePush(root, local, { remote = absent, url = publicUrl, env } = {}) {
  const localRef = local === absent ? "(delete)" : branch;
  return runCheck(
    root,
    ["--pre-push", "origin", url],
    `${localRef} ${local} ${branch} ${remote}\n`,
    env,
  );
}

function push(root, remote) {
  installCheck(root);
  mkdirSync(join(root, ".git", "hooks"), { recursive: true });
  writeFileSync(
    join(root, ".git", "hooks", "pre-push"),
    `#!/bin/sh\nexec "${process.execPath}" ${guardFiles[0]} --pre-push "$@"\n`,
    { mode: 0o755 },
  );
  return spawnSync("git", ["push", remote, branch], {
    cwd: root,
    encoding: "utf8",
    env: localSshEnv(root),
  });
}

function expectRefusal(result, commit, path) {
  expect(result.status, result.stderr).toBe(1);
  expect(result.stderr).toContain(commit);
  expect(result.stderr).toContain(path);
  expect(result.stderr).toMatch(/remove/i);
}

it("refuses_a_commit_holding_the_engine_crate", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const contents = "fn concealed_fixture() {}";
  const commit = commitFile(root, privatePath, contents);
  const url = "git@github.com:brambleworks/SiteCMD-Local.git";
  const result = prePush(root, commit, { url });
  expectRefusal(result, commit, privatePath);
  expect(result.stderr).not.toContain(contents);
});

it("refuses_a_cargo_lock_naming_sitecmd_code_scan", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const crate = ["sitecmd", "code", "scan"].join("-");
  const file = "nested/Cargo.lock";
  const commit = commitFile(root, file, `[[package]]\nname = "${crate}"\nversion = "1.0.0"\n`);
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toContain(crate);
});

it("allows_sitecmd_engine_host", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const commit = commitFile(root, "Cargo.toml", '[package]\nname = "sitecmd-engine-host"\n');
  expect(prePush(root, commit)).toMatchObject({ status: 0, stderr: "" });
});

it("allows_wire_identifiers_json", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const file = `${workspace}/tests/fixtures/parity/wire_identifiers.json`;
  const commit = commitFile(root, file, "{}\n");
  expect(prePush(root, commit)).toMatchObject({ status: 0, stderr: "" });
});

it.each(["assets/nested/fixture.wasm", "assets/engine.WASM"])(
  "refuses_a_wasm_file_anywhere (%s)",
  (file) => {
    // Engine code reaching the public repository. The WASM suffix check missed uppercase files.
    const root = repository();
    const commit = commitFile(root, file, Buffer.from([0, 97, 115, 109]));
    expectRefusal(prePush(root, commit), commit, file);
  },
);

it("refuses_prebuilt_engine_libraries_by_basename", () => {
  // Prebuilt engine libraries escaped the path and source scans.
  const root = repository();
  const names = [
    engineRustName,
    engineRustName + "_wasm",
    engineRustName + "_fuzz",
    ["sitecmd", "code", "scan"].join("_"),
    ["sitecmd", "local", "engine"].join("_"),
  ];
  const files = [
    `assets/lib${names[0]}-abc.rlib`,
    `assets/${names[1].toUpperCase()}-def.RMETA`,
    `assets/lib${names[2]}.a`,
    `assets/${names[3]}.so`,
    `assets/lib${names[4]}.dylib`,
    `assets/${names[0]}.dll`,
    `assets/${names[3]}.lib`,
  ];
  const allowed = [
    "assets/libsitecmd_engine_host-abc.rlib",
    "assets/SITECMD_ENGINE_HOST.DLL.LIB",
    `assets/${engineRustName}.txt`,
    `assets/${engineRustName}/unrelated.a`,
  ];
  for (const file of [...files, ...allowed]) {
    mkdirSync(dirname(join(root, file)), { recursive: true });
    writeFileSync(join(root, file), "fixture");
  }
  const commit = commitFile(root, "README.md", "# Public\n");
  const result = prePush(root, commit);
  for (const file of files) expectRefusal(result, commit, file);
  for (const file of allowed) expect(result.stderr).not.toContain(file);
});

const escapedCrate = String.raw`sitecmd-\u0065ngine`;
it.each([
  ["Cargo.toml", `[dependencies]\nalias = { package = "${escapedCrate}", version = "1" }\n`],
  ["nested/Cargo.lock", `[[package]]\nname = "${escapedCrate}"\nversion = "1.0.0"\n`],
  ["nested/CaRgO.ToMl", '[package]\nname = "' + ["sitecmd", "engine"].join("-") + '"\n'],
  ["CARGO.LOCK", '[[package]]\nname = "' + ["sitecmd", "code", "scan"].join("-") + '"\n'],
])("refuses_private_crate_names_in_cargo_files (%s)", (file, contents) => {
  // Engine code reaching the public repository. Escaped names and odd-case manifests were missed.
  const root = repository();
  const commit = commitFile(root, file, contents);
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toMatch(/names the private crate/);
});

it.each([
  ["Cargo.toml", '[package]\nname = "%s"\n'],
  ["Cargo.toml", '[dependencies]\nalias = { package = "%s", version = "1" }\n'],
  ["nested/Cargo.lock", '[[package]]\nname = "%s"\nversion = "1.0.0"\n'],
  [".cargo/config.toml", '[patch.crates-io]\n"%s" = { path = "x" }\n'],
])("refuses_private_crate_names_with_toml_byte_escapes (%s, %s)", (file, format) => {
  // TOML byte escapes hid engine crate names from the Cargo check.
  const root = repository();
  const commit = commitFile(root, file, format.replace("%s", String.raw`sitecmd-\x65ngine`));
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toMatch(/names the private crate/);
});

it.each(pathspecVars)("checks_cargo_and_rust_with_%s_set", (variable) => {
  // Inherited Git pathspec settings could disable or alter the crate scan.
  const root = repository();
  const manifest = "nested/CARGO.TOML";
  const cargoCommit = commitFile(root, manifest, `[package]\nname = "${engineCargoName}"\n`);
  const rustFile = "src/glue.RS";
  const rustCommit = commitFile(root, rustFile, `pub use ${engineRustName}::scan;\n`);
  const env = localSshEnv(root);
  const result = prePush(root, rustCommit, {
    env: { ...env, [variable]: "1" },
  });
  expectRefusal(result, cargoCommit, manifest);
  expectRefusal(result, rustCommit, rustFile);
  expect(readFileSync(env.SITECMD_TEST_SSH_LOG, "utf8")).not.toContain(variable);
});

function commitCrateReferences(root) {
  writeFileSync(join(root, "Cargo.toml"), `[package]\nname = "${engineCargoName}"\n`);
  return commitFile(root, "src/glue.rs", `pub use ${engineRustName}::scan;\n`);
}

it("checks_cargo_and_rust_with_an_ancestor_work_tree", () => {
  // An inherited GIT_WORK_TREE narrowed the crate scan to the working directory prefix.
  const root = repository();
  const commit = commitCrateReferences(root);
  const result = prePush(root, commit, {
    env: { ...localSshEnv(root), GIT_WORK_TREE: dirname(root) },
  });
  expectRefusal(result, commit, "Cargo.toml");
  expectRefusal(result, commit, "src/glue.rs");
});

it.each([
  ["app/Cargo.toml", "../docs/manifest.txt", `[package]\nname = "${engineCargoName}"\n`],
  ["src/glue.rs", "../docs/glue.txt", `pub use ${engineRustName}::scan;\n`],
  ["app/CARGO.LOCK", "../docs/lock.txt", `[[package]]\nname = "${engineCargoName}"\n`],
  [".cargo/config", "../docs/config.txt", "fixture\n"],
  ["nested/.CARGO/CONFIG.TOML", "../../docs/config.txt", "fixture\n"],
  ["src/open.RS", "../docs/missing.txt", undefined],
])("refuses_symlinked_crate_scan_inputs (%s)", (file, target, contents) => {
  // Git grep read symlink text while Cargo or Rust could follow the link.
  const root = repository();
  if (contents !== undefined) commitFile(root, join(dirname(file), target), contents);
  mkdirSync(dirname(join(root, file)), { recursive: true });
  symlinkSync(target, join(root, file));
  const commit = commitFile(root, "README.md", "# Public\n");
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toContain("symbolic link");
});

it.each([".cargo", "app/.CARGO/included"])(
  "refuses_symlinks_in_cargo_config_paths (%s)",
  (file) => {
    // Cargo followed a link at or under its configuration directory.
    const root = repository();
    const target = "docs/cargo-settings/config.toml";
    commitFile(root, target, `[patch.crates-io]\n${engineCargoName} = { path = "x" }\n`);
    mkdirSync(dirname(join(root, file)), { recursive: true });
    symlinkSync(join(root, dirname(target)), join(root, file));
    const commit = commitFile(root, "README.md", "# Public\n");
    const result = prePush(root, commit);
    expectRefusal(result, commit, file);
    expect(result.stderr).toContain("symbolic link");
  },
);

it("refuses_private_crate_names_in_included_cargo_configuration", () => {
  // Cargo include files could name private crates outside the standard configuration filenames.
  const root = repository();
  const file = "app/.cargo/settings/engine.toml";
  commitFile(root, "app/.cargo/config.toml", 'include = ["settings/engine.toml"]\n');
  const commit = commitFile(root, file, `[patch.crates-io]\n${engineCargoName} = { path = "x" }\n`);
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toMatch(/names the private crate/);
});

it.each([
  [".cargo/config.toml", 'include = ["../docs/build-settings.toml"]'],
  [".cargo/config", "include = '../docs/build-settings.toml'"],
  [
    "app/.CARGO/settings/base.toml",
    String.raw`"incl\u0075de" = ["..\x2f../docs/build-settings.toml"]`,
  ],
  [
    ".cargo/config.toml",
    'include = [{ path = "inside.toml", optional = true }, { path = "../docs/build-settings.toml" }]',
  ],
  [".cargo/config.toml", '[[include]]\npath = "../docs/build-settings.toml"'],
  [".cargo/config.toml", 'include = "/docs/build-settings.toml"'],
  [".cargo/config.toml", "include = '..\\docs\\build-settings.toml'"],
  [".cargo/config.toml", "include = 'child\\dir/../../docs/build-settings.toml'"],
  [".cargo/config.toml", 'include = "../docs/../.cargo/inside.toml"'],
])("refuses_cargo_includes_escaping_the_config_directory (%s, %s)", (file, config) => {
  // Cargo could load configuration outside the tree guard's .cargo scan.
  const root = repository();
  const base = commitFile(
    root,
    "docs/build-settings.toml",
    `[patch.crates-io]\n${engineCargoName} = { path = "x" }\n`,
  );
  const commit = commitFile(root, file, config + "\n");
  const result = prePush(root, commit, { remote: base });
  expectRefusal(result, commit, file);
  expect(result.stderr).toContain("includes a file outside its .cargo directory");
});

it("allows_nested_cargo_includes_that_stay_in_the_config_directory", () => {
  // Confining Cargo includes must still allow a nested config to include its parent directory.
  const root = repository();
  commitFile(root, "app/.cargo/config.toml", 'include = ["settings/base.toml"]\n');
  commitFile(root, "app/.cargo/settings/base.toml", 'include = ["../shared.toml"]\n');
  const commit = commitFile(root, "app/.cargo/shared.toml", "[build]\njobs = 2\n");
  expect(prePush(root, commit)).toMatchObject({ status: 0, stderr: "" });
});

it.each([
  ["Cargo.toml", "[package]"],
  ["Cargo.lock", "[[package]]"],
])("refuses_crate_names_after_multiline_strings (%s)", (file, header) => {
  // Extra quotes at the end of a TOML string hid the following crate name.
  const root = repository();
  const crate = ["sitecmd", "engine"].join("-");
  const contents = `${header}\ndescription = """x""""\nname = "${crate}"\nversion = "1.0.0"\n`;
  const commit = commitFile(root, file, contents);
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toContain(crate);
});

it("refuses_a_raw_cargo_crate_name_outside_decoded_fields", () => {
  // Reading only parsed fields let raw crate names through the Cargo check.
  const root = repository();
  const crate = ["sitecmd", "engine"].join("-");
  const commit = commitFile(root, "Cargo.toml", `[package]\nname = "public"\n# ${crate}\n`);
  const result = prePush(root, commit);
  expectRefusal(result, commit, "Cargo.toml");
  expect(result.stderr).toContain(crate);
});

it.each([".cargo/config.toml", "nested/.cargo/config"])(
  "refuses_private_crate_patches_in_cargo_config (%s)",
  (file) => {
    // The Cargo pathspec missed crate patches set in Cargo configuration.
    const root = repository();
    const commit = commitFile(
      root,
      file,
      `[patch.crates-io]\n"${escapedCrate}" = { path = "x" }\n`,
    );
    const result = prePush(root, commit);
    expectRefusal(result, commit, file);
    expect(result.stderr).toMatch(/names the private crate/);
  },
);

it.each([
  `${workspace}/src/${["ai", "mod.rs"].join("/")}`,
  `${workspace}/src/core/${["confidence_policy", "mod.rs"].join("/")}`,
  ".github/workflows/" + ["publish", "capability", "manifest.yaml"].join("-"),
])("refuses_engine_paths_with_alternate_file_layouts (%s)", (file) => {
  // Private Rust modules and workflows could use the alternate file layout.
  const root = repository();
  const commit = commitFile(root, file, "private\n");
  expectRefusal(prePush(root, commit), commit, file);
});

it.each([
  privatePath.replace(/^apps/, "Apps"),
  [workspace, "src", "checks.rs"].join("/"),
  [workspace, "src", "scoring.rs"].join("/"),
  [workspace, "src", "core", "code_scan.rs"].join("/"),
  privatePath.split("/").slice(0, -2).join("/"),
  [workspace, "tests", "fixtures", "PARITY", "WIRE_IDENTIFIERS.JSON"].join("/"),
])("refuses_alternate_forms_of_engine_paths (%s)", (file) => {
  // Engine code reaching the public repository. Case aliases and module files bypassed the prefix check.
  const root = repository();
  const commit = commitFile(root, file, "private\n");
  expectRefusal(prePush(root, commit), commit, file);
});

it("refuses_a_gitlink_at_an_engine_directory", () => {
  // Engine code reaching the public repository. The gitlink path lacked a trailing slash.
  const root = repository();
  const base = commitFile(root, "README.md", "# Public\n");
  const file = privatePath.split("/").slice(0, -2).join("/");
  git(root, "update-index", "--add", "--cacheinfo", `160000,${base},${file}`);
  git(root, "commit", "--quiet", "-m", "Add fixture link");
  const commit = git(root, "rev-parse", "HEAD");
  expectRefusal(prePush(root, commit, { remote: base }), commit, file);
});

it("checks_every_pushed_commit_not_only_the_tip", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const base = commitFile(root, "README.md", "# Public\n");
  git(root, "update-ref", "refs/remotes/origin/main", base);
  const commit = commitFile(root, privatePath, "private\n");
  const tip = commitFile(root, privatePath);
  expectRefusal(prePush(root, tip, { remote: base }), commit, privatePath);
  expectRefusal(runCheck(root, ["--pull-request", base, tip]), commit, privatePath);
});

function runTreeSelector(root, base, head, runnerTemp = join(root, ".git", "runner temp")) {
  mkdirSync(runnerTemp, { recursive: true });
  const ci = readFileSync(new URL("../../.github/workflows/ci.yml", import.meta.url), "utf8");
  const command = readWorkflow(ci).jobs["public-tree"].steps.find(({ run }) =>
    run?.startsWith("selector="),
  ).run;
  return spawnSync("bash", ["-e", "-c", command], {
    cwd: root,
    encoding: "utf8",
    env: { ...gitEnv, BASE_SHA: base, HEAD_SHA: head, RUNNER_TEMP: runnerTemp },
  });
}

it("checks_pull_request_crate_references_with_runner_temp_inside_the_checkout", () => {
  // A temporary guard inside the working tree narrowed the crate scan to its own directory.
  const root = repository();
  installCheck(root);
  const base = commitFile(root, "README.md", "# Public\n");
  const commit = commitCrateReferences(root);
  const result = runTreeSelector(root, base, commit, join(root, "runner temp"));
  expectRefusal(result, commit, "Cargo.toml");
  expectRefusal(result, commit, "src/glue.rs");
});

it.each(["guard", "path list"])("checks_pull_requests_with_the_base_copy_of_the_%s", (changed) => {
  // Engine code reaching the public repository. A pull request could change the code checking its commits.
  const root = repository();
  installCheck(root);
  const base = commitFile(root, "README.md", "# Public\n");
  const offending = commitFile(root, privatePath, "private\n");
  const [script, rules] = guardFiles;
  const pathList = join(root, rules);
  if (changed === "guard") {
    writeFileSync(join(root, script), "process.exit(0);\n");
  } else {
    writeFileSync(
      pathList,
      readFileSync(pathList, "utf8").replace(
        /export const ENGINE_PATHS = \[[\s\S]*?\];/,
        "export const ENGINE_PATHS = [];",
      ),
    );
  }
  git(root, "add", "--all");
  git(root, "commit", "--quiet", "-m", "Update fixture");
  const head = git(root, "rev-parse", "HEAD");
  expectRefusal(runTreeSelector(root, base, head), offending, privatePath);
});

it("uses_the_head_guard_when_the_base_has_no_guard_files", () => {
  // The first pull request could not use a guard absent from its base.
  const root = repository();
  const base = commitFile(root, "README.md", "# Public\n");
  installCheck(root);
  const head = commitFile(root, "CHANGELOG.md", "# Public changes\n");
  expect(runTreeSelector(root, base, head)).toMatchObject({ status: 0, stderr: "" });
  const offending = commitFile(root, privatePath, "private\n");
  expectRefusal(runTreeSelector(root, base, offending), offending, privatePath);
});

it.each(["missing parser", "missing mode", "selector only"])(
  "refuses_a_pull_request_with_an_incomplete_base_guard (%s)",
  (incomplete) => {
    // An incomplete base guard let a pull request select its own check.
    const root = repository();
    installCheck(root);
    if (incomplete === "missing parser") rmSync(join(root, guardFiles[2]));
    if (incomplete === "missing mode") {
      writeFileSync(join(root, guardFiles[0]), "process.exit(0);\n");
    }
    if (incomplete === "selector only") {
      for (const file of guardFiles) rmSync(join(root, file));
    }
    const base = commitFile(root, "README.md", "# Public\n");
    installCheck(root);
    writeFileSync(join(root, selector), "process.exit(0);\n");
    for (const head of [
      commitFile(root, "CHANGELOG.md", "# Public changes\n"),
      commitFile(root, privatePath, "private\n"),
    ]) {
      const result = runTreeSelector(root, base, head);
      expect(result.status, result.stderr).toBe(2);
      expect(result.stderr).toMatch(/base.*public tree guard/i);
    }
  },
);

it.each(["missing selector", "legacy guard"])(
  "uses_the_head_guard_when_the_base_lacks_the_selector (%s)",
  (legacy) => {
    // The pull request that adds the selector was refused because its base holds the older guard.
    const root = repository();
    installCheck(root);
    rmSync(join(root, selector));
    if (legacy === "legacy guard") {
      rmSync(join(root, guardFiles[2]));
      writeFileSync(join(root, guardFiles[0]), "process.exit(0);\n");
    }
    const base = commitFile(root, "README.md", "# Public\n");
    installCheck(root);
    const head = commitFile(root, "CHANGELOG.md", "# Public changes\n");
    expect(runTreeSelector(root, base, head)).toMatchObject({ status: 0, stderr: "" });
    const offending = commitFile(root, privatePath, "private\n");
    expectRefusal(runTreeSelector(root, base, offending), offending, privatePath);
  },
);

it.each(["selector", ...guardFiles])("refuses_a_pull_request_that_removes_the_guard_%s", (file) => {
  // Removing the selector let the next pull request run a check of its own choosing.
  const root = repository();
  installCheck(root);
  const base = commitFile(root, "README.md", "# Public\n");
  rmSync(join(root, file === "selector" ? selector : file));
  git(root, "add", "--all");
  git(root, "commit", "--quiet", "-m", "Update fixture");
  const result = runTreeSelector(root, base, git(root, "rev-parse", "HEAD"));
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toMatch(/removes part of the public tree guard/);
});

it("the pre-push hook forwards public updates to the history check", () => {
  const root = repository();
  installCheck(root);
  const commit = commitFile(root, privatePath, "private\n");
  const script = new URL("../../.lefthook/pre-push/public-tree.sh", import.meta.url);
  const result = spawnSync("sh", [fileURLToPath(script), "origin", publicUrl], {
    cwd: root,
    encoding: "utf8",
    env: localSshEnv(root),
    input: `${branch} ${commit} ${branch} ${absent}\n`,
  });
  expectRefusal(result, commit, privatePath);
});

it("refuses_an_engine_path_when_only_another_remote_has_the_commit", () => {
  // Engine code reaching the public repository. A private tracking ref hid the outgoing commit.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  expectRefusal(prePush(root, commit), commit, privatePath);
  git(root, "remote", "add", "origin", "https://private.example.net/team/engine.git");
  git(root, "update-ref", "refs/remotes/origin/main", commit);
  expectRefusal(prePush(root, commit), commit, privatePath);
});

it("subtracts_only_public_history_when_multiple_refs_are_pushed", () => {
  // Engine code reaching the public repository. A private tracking ref hid one outgoing ref.
  const root = repository();
  const clean = commitFile(root, "README.md", "# Public\n");
  const privateCommit = commitFile(root, privatePath, "private\n");
  git(root, "update-ref", "refs/remotes/origin/main", privateCommit);
  const cleanUpdate = `${branch} ${clean} ${branch} ${absent}\n`;
  const other = "refs/heads/other";
  const dirtyUpdate = `${other} ${privateCommit} ${other} ${clean}\n`;
  expectRefusal(
    runCheck(root, ["--pre-push", "public", publicUrl], cleanUpdate + dirtyUpdate),
    privateCommit,
    privatePath,
  );
  seedBare(join(root, ".git", "public.git"), root, privateCommit);
  expect(
    runCheck(root, ["--pre-push", "public", publicUrl], cleanUpdate + dirtyUpdate),
  ).toMatchObject({
    status: 0,
    stderr: "",
  });
});

it("subtracts_the_remote_commit_advertised_for_a_deleted_ref", () => {
  // Engine code reaching the public repository. Deletion records lost their public history boundary.
  const root = repository();
  const base = commitFile(root, privatePath, "previously public\n");
  const clean = commitFile(root, privatePath);
  const added = `${branch} ${clean} ${branch} ${absent}\n`;
  const removed = `(delete) ${absent} refs/heads/old ${base}\n`;
  expectRefusal(runCheck(root, ["--pre-push", "public", publicUrl], added), base, privatePath);
  expect(runCheck(root, ["--pre-push", "public", publicUrl], added + removed)).toMatchObject({
    status: 0,
    stderr: "",
  });
});

it("refuses_a_copied_private_blob_under_an_open_path", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const privateClone = repository();
  const contents = "fn copied_fixture() {}\n";
  commitFile(privateClone, privatePath, contents);
  commitFile(privateClone, privatePath);
  git(root, "config", "sitecmd.privateClone", privateClone);
  git(root, "remote", "add", "origin", publicUrl);
  const file = `${workspace}/src/core/audit/open.rs`;
  const commit = commitFile(root, file, contents);
  git(root, "update-ref", "refs/remotes/private/main", commit);
  const tip = commitFile(root, "README.md", "# Public\n");
  const result = prePush(root, tip);
  expectRefusal(result, tip, file);
  expect(result.stderr).not.toContain(contents);
});

it("refuses_a_private_blob_when_only_another_remote_has_the_commit", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const privateClone = repository();
  const contents = "fn private_remote_fixture() {}\n";
  commitFile(privateClone, privatePath, contents);
  git(root, "config", "sitecmd.privateClone", privateClone);
  const file = "src/copied.rs";
  const commit = commitFile(root, file, contents);
  git(root, "update-ref", "refs/remotes/private/main", commit);
  expectRefusal(prePush(root, commit), commit, file);
});

const moveList = "tools/scripts/published-engine-moves.json";

function publishedMoveFixture() {
  const root = repository();
  const privateClone = repository();
  const moved = "fn moved_fixture() {}\n";
  const other = "fn other_fixture() {}\n";
  const first = commitFile(privateClone, privatePath, moved);
  commitFile(privateClone, privatePath, other);
  git(root, "config", "sitecmd.privateClone", privateClone);
  const path = "src/moved.rs";
  const blob = git(privateClone, "rev-parse", `${first}:${privatePath}`);
  return { root, path, blob, moved, other };
}

function moveListText(moves, approved = "Approved fixture") {
  return JSON.stringify({ approved, moves }) + "\n";
}

it("accepts_a_listed_move_at_its_listed_path", () => {
  const { root, path, blob, moved } = publishedMoveFixture();
  commitFile(root, moveList, moveListText([{ path, blob }]));
  const commit = commitFile(root, path, moved);
  const result = prePush(root, commit);
  expect(result.status, result.stderr).toBe(0);
});

it("refuses_a_listed_blob_at_another_path", () => {
  const { root, path, blob, moved } = publishedMoveFixture();
  const otherPath = "src/copied.rs";
  commitFile(root, moveList, moveListText([{ path, blob }]));
  commitFile(root, path, moved);
  const commit = commitFile(root, otherPath, moved);
  const result = prePush(root, commit);
  expectRefusal(result, commit, otherPath);
  expect(result.stderr).not.toContain(JSON.stringify(path));
});

it("refuses_an_unlisted_private_blob_at_a_listed_path", () => {
  const { root, path, blob, moved, other } = publishedMoveFixture();
  commitFile(root, moveList, moveListText([{ path, blob }]));
  const approvedCommit = commitFile(root, path, moved);
  const commit = commitFile(root, path, other);
  const result = prePush(root, commit);
  expectRefusal(result, commit, path);
  expect(result.stderr).not.toContain(approvedCommit);
});

it("refuses_an_uncommitted_move_list", () => {
  const { root, blob, moved } = publishedMoveFixture();
  const file = "src/leak.rs";
  const commit = commitFile(root, file, moved);
  mkdirSync(dirname(join(root, moveList)), { recursive: true });
  writeFileSync(join(root, moveList), moveListText([{ path: file, blob }]));
  expectRefusal(prePush(root, commit), commit, file);
});

it("applies_the_list_from_the_pushed_commit", () => {
  const { root, path, blob, moved } = publishedMoveFixture();
  mkdirSync(dirname(join(root, moveList)), { recursive: true });
  writeFileSync(join(root, moveList), moveListText([{ path, blob }]));
  const commit = commitFile(root, path, moved);
  commitFile(root, moveList);
  expect(prePush(root, commit)).toMatchObject({ status: 0, stderr: "" });
});

it("refuses_a_move_approved_only_by_a_later_commit", () => {
  const { root, path, blob, moved } = publishedMoveFixture();
  const unapprovedCommit = commitFile(root, path, moved);
  const approvedCommit = commitFile(root, moveList, moveListText([{ path, blob }]));
  const result = prePush(root, approvedCommit);
  expectRefusal(result, unapprovedCommit, path);
  expect(result.stderr).not.toContain(approvedCommit);
});

it.each([
  ["missing blob", ({ path }) => moveListText([{ path }]), "entry 1 requires a blob object ID"],
  ["missing path", ({ blob }) => moveListText([{ blob }]), "requires a repository-relative path"],
  [
    "non-hex blob",
    ({ path }) => moveListText([{ path, blob: "x".repeat(40) }]),
    "entry 1 requires a blob object ID",
  ],
  [
    "duplicate path",
    ({ path, blob }) =>
      moveListText([
        { path, blob },
        { path, blob },
      ]),
    "duplicate path",
  ],
  ["empty approved", () => moveListText([], ""), "expected an approved statement"],
  ["invalid JSON", () => "{", "Malformed"],
  ["empty file", () => "", "Malformed"],
  [
    "duplicate top-level keys",
    ({ path, blob }) => `{"moves":[],${moveListText([{ path, blob }]).slice(1)}`,
    'duplicate top-level key "moves"',
  ],
  [
    // Bug: a repeated key inside an entry let the last path win and exempt another file.
    "duplicate keys in an entry",
    ({ path, blob }) =>
      `{"approved":"Approved.","moves":[{"path":${JSON.stringify(path)},"blob":"${blob}","path":"src/leak.rs"}]}`,
    'duplicate key "path" in an entry',
  ],
  [
    "escaped duplicate top-level keys",
    () => '{"approved":"First","approv\\u0065d":"Second","moves":[]}',
    'duplicate top-level key "approved"',
  ],
])("refuses_a_malformed_move_list (%s)", (_, contents, diagnostic) => {
  const fixture = publishedMoveFixture();
  const { root } = fixture;
  const commit = commitFile(root, moveList, contents(fixture));
  const result = prePush(root, commit);
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain(moveList);
  expect(result.stderr).toContain(diagnostic);
});

it("ignores_blobs_already_public", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const contents = "fn shared_fixture() {}\n";
  const base = commitFile(root, "src/shared.rs", contents);
  seedBare(join(root, ".git", "public.git"), root, base);
  commitFile(root, "src/shared.rs");
  const privateClone = repository();
  commitFile(privateClone, privatePath, contents);
  git(root, "config", "sitecmd.privateClone", privateClone);
  const commit = commitFile(root, "src/copied.rs", contents);
  expect(prePush(root, commit)).toMatchObject({ status: 0, stderr: "" });
});

it.each([
  `git@github.com:${privateRepository}.git`,
  `https://github.com/${privateRepository}.git`,
  `https://github.com:22/${privateRepository}.git`,
  `https://github.com:443/${privateRepository}.git`,
  `ssh://git@github.com/${privateRepository}.git`,
  `ssh://git@github.com:22/${privateRepository}.git`,
  `ssh://git@SSH.GITHUB.COM:443/${privateRepository}.git`,
  `git+ssh://git@github.com/${privateRepository}.git`,
  `git://github.com/${privateRepository}.git`,
  "a+1.b-c::https::https://github.com//BRAMBLEWORKS//SiteCMD-ENGINE.GIT//?query#fragment",
])("skips_the_known_private_push_destination (%s)", (url) => {
  // The private engine destination must accept its own engine paths.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  const env = localSshEnv(root, join(root, "unavailable.git"));
  expect(prePush(root, commit, { url, env })).toMatchObject({ status: 0, stdout: "", stderr: "" });
});

it.each([
  `https://gitlab.com/${privateRepository}.git`,
  `s3://storage.example.net/${privateRepository}.git`,
  `https://www.github.com/${privateRepository}.git`,
  `git@github-brambleworks:${privateRepository}.git`,
  `https://github.com@code.example.net/${privateRepository}.git`,
])("checks_private_repository_names_on_other_hosts (%s)", (url) => {
  // A matching repository path on another host bypassed the public tree check.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  rewriteLookup(root, url);
  expectRefusal(prePush(root, commit, { url }), commit, privatePath);
});

it.each([
  `ssh::ssh://git@github.com/extra/%2e%2e/${privateRepository}.git`,
  `git@github.com:extra/../${privateRepository}.git`,
  `ssh://git@github.com/${privateRepository}.git whitespace`,
  `ssh+git://git@github.com/extra%3Fquery/../${privateRepository}.git`,
  `git@github.com:extra%23fragment/../${privateRepository}.git`,
  `git+ssh://git@github.com/extra%20space/../${privateRepository}.git`,
])("checks_ambiguous_raw_ssh_paths (%s)", (url) => {
  // Git sends the raw SSH path, while clipping or normalizing it could exempt another repository.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  rewriteLookup(root, url);
  expectRefusal(prePush(root, commit, { url }), commit, privatePath);
});

it.each([
  `ssh://[evil.example]@github.com/${privateRepository}.git`,
  `ssh://git@[evil.example]@github.com/${privateRepository}.git`,
  `[evil.example]@github.com:${privateRepository}.git`,
  `git://[evil.example]@github.com/${privateRepository}.git`,
  `git@[github.com]:${privateRepository}.git`,
  `git@github.com:${privateRepository}.git#/../../brambleworks/SiteCMD-Local.git`,
  `ssh://git@github.com/${privateRepository}.git?/../../brambleworks/SiteCMD-Local.git`,
  `ssh://git@github.com/${privateRepository}.git?query`,
  `git://github.com/${privateRepository}.git#fragment`,
])("checks_bracketed_hosts_and_raw_ssh_queries (%s)", (url) => {
  // Git connected to a bracketed host, or sent a raw ssh path past ? or #, while the push was exempt.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  rewriteLookup(root, url);
  expectRefusal(prePush(root, commit, { url }), commit, privatePath);
});

it.each(
  ["", "https::"].flatMap((transport) =>
    ["\u00a0", "\u1680", "\u2028", "\u202f", "\u3000", "\ufeff"].map(
      (space) =>
        `${transport}https://github.com/${privateRepository}.git${space}/../SiteCMD-Local.git`,
    ),
  ),
)("checks_urls_with_unicode_whitespace_before_a_dot_segment (%j)", (url) => {
  // Unicode whitespace truncated the path before curl could remove its dot segment.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  rewriteLookup(root, url);
  expectRefusal(prePush(root, commit, { url }), commit, privatePath);
});

it.each([
  `ssh://git@github.com/${privateRepository.replaceAll("-", "%2D")}.git`,
  "a+1.b-c::https::https://github.com//BRAMBLEWORKS/./extra/../SiteCMD%2dEngine.GIT//",
  `https://github.com/extra/../${privateRepository}.git`,
  `https://github.com/${privateRepository}.git\t`,
  `https://github.com/${privateRepository}.git?x=%20`,
  `https://github.com/${privateRepository}.git#\u007f`,
])("checks_nonexact_private_destination_spellings (%j)", (url) => {
  // Normalization or clipping let nonexact URLs take the private exemption.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  rewriteLookup(root, url);
  expectRefusal(prePush(root, commit, { url }), commit, privatePath);
});

it("matches_the_public_url_path_across_hosts_and_transports", () => {
  // Engine code reaching the public repository. An SSH host alias skipped the public check.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  const urls = [
    publicUrl,
    "https://github.com/brambleworks/SiteCMD-Local.git",
    "ssh://git@github.com/brambleworks/SiteCMD-Local",
    "ssh://git@ssh.github.com:443/brambleworks/SiteCMD-Local.git/",
    "HTTPS://GITHUB.COM/BRAMBLEWORKS/SITECMD-LOCAL.GIT/",
    "git@github-brambleworks:brambleworks/SiteCMD-Local.git",
    "https://code.example.net/brambleworks/SiteCMD-Local/",
    "git@github.com:/brambleworks/SiteCMD-Local.git",
    "https://github.com/brambleworks/SiteCMD-Local.git?x",
    "https://github.com/brambleworks/SiteCMD-Local.git/info/../",
    "git@github-brambleworks:brambleworks/SiteCMD-Local-archive",
  ];
  for (const url of urls) {
    if (/^https:/i.test(url)) rewriteLookup(root, url);
    const result = prePush(root, commit, { url });
    expect(result.status, url).toBe(1);
    expectRefusal(result, commit, privatePath);
  }
});

it.each([
  "https://code.example.net/brambleworks//SiteCMD-Local.git",
  "https://code.example.net/brambleworks/SiteCMD-Local.git//",
  "https://code.example.net/brambleworks/./extra/../SiteCMD-Local.git",
  "https://code.example.net/brambleworks/SiteCMD.git",
  "git@code.example.net:brambleworks/SiteCMD-app.git",
  "ssh://git@code.example.net/brambleworks-co/SiteCMD.git",
  "https::https://github.com/brambleworks/SiteCMD-Local.git",
  "git://code.example.net/brambleworks/SiteCMD%2DLocal.git",
  "ssh://git@github.com/brambleworks-co/SiteCMD-app.git",
  "ssh://git@github.com/someone/SiteCMD-Local.git",
  "ssh://git@github.com/example/another.git",
  `ssh://git@github.com/${privateRepository}-archive.git`,
  `ssh://git@github.com/${privateRepository.replace("-", "%ZZ")}.git`,
])("checks_normalized_public_paths_and_repository_aliases (%s)", (url) => {
  // Path aliases let a push reach the public repository without being checked.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  if (/^(?:https:|git:\/\/)/i.test(url)) rewriteLookup(root, url);
  if (url.includes("%ZZ")) rewriteLookup(root, url);
  expectRefusal(prePush(root, commit, { url }), commit, privatePath);
});

it.each([
  "brambleworks/SiteCMD%2DLocal.git",
  "%62rambleworks/SiteCMD-Local.git",
  "brambleworks%2FSiteCMD-Local.git",
])("refuses_an_ssh_push_with_a_percent_encoded_repository_path (%s)", (path) => {
  // Git decoded the SSH repository path after the guard skipped the encoded spelling.
  const root = repository();
  git(root, "remote", "add", "public", `ssh://git@github.com/${path}`);
  const commit = commitFile(root, privatePath, "private\n");
  expectRefusal(push(root, "public"), commit, privatePath);
  expect(readFileSync(join(root, ".git", "local-ssh.log"), "utf8")).toContain(
    "git-receive-pack '/brambleworks/SiteCMD-Local.git'",
  );
  expect(git(join(root, ".git", "public.git"), "rev-list", "--all")).toBe("");
});

it("ignores_an_insteadof_mirror_when_pushinsteadof_reaches_the_push_server", () => {
  // An insteadOf lookup read a mirror that already held the commit absent from the push server.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  const mirror = join(root, ".git", "mirror.git");
  git(root, "init", "--quiet", "--bare", mirror);
  seedBare(mirror, root, commit);
  git(root, "remote", "add", "public", "fixture-alias:");
  git(root, "config", `url.${publicUrl}.pushInsteadOf`, "fixture-alias:");
  rewriteLookup(root, publicUrl, mirror);
  expect(git(root, "remote", "get-url", "--push", "public")).toBe(publicUrl);
  expect(git(root, "ls-remote", "--get-url", publicUrl)).toBe(pathToFileURL(mirror).href);
  expectRefusal(push(root, "public"), commit, privatePath);
  const server = join(root, ".git", "public.git");
  expect(git(server, "rev-list", "--all")).toBe("");
  expect(readFileSync(join(root, ".git", "local-ssh.log"), "utf8")).not.toContain(
    "git-upload-pack",
  );
  seedBare(server, root, commit);
  const clean = commitFile(root, privatePath);
  const update = push(root, "public");
  expect(update.status, update.stderr).toBe(0);
  expect(git(server, "rev-parse", branch)).toBe(clean);
});

it("distinguishes_a_rewritten_repository_path_with_trailing_whitespace", () => {
  // Trimming the resolved URL would conflate two distinct repository paths.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  seedBare(join(root, ".git", "public.git"), root, commit);
  git(root, "config", `url.${publicUrl} .insteadOf`, publicUrl);
  expectRefusal(prePush(root, commit), commit, privatePath);
  expect(() => readFileSync(join(root, ".git", "local-ssh.log"))).toThrow(/ENOENT/);
});

it.each(["mirror", "hand-moved ref"])(
  "ignores_a_%s_when_the_push_server_lacks_the_commit",
  (kind) => {
    // A tracking ref could claim engine commits were already public while the push server lacked them.
    const root = repository();
    const commit = commitFile(root, privatePath, "private\n");
    git(
      root,
      "remote",
      "add",
      "tracking",
      "https://tracking.example.net/brambleworks/SiteCMD-Local.git",
    );
    const tracking = "refs/remotes/tracking/main";
    if (kind === "mirror") {
      const mirror = join(root, ".git", "mirror.git");
      git(root, "init", "--quiet", "--bare", mirror);
      seedBare(mirror, root, commit);
      git(root, "remote", "set-url", "--push", "tracking", pathToFileURL(mirror).href);
      git(root, "fetch", "--quiet", pathToFileURL(mirror).href, `${branch}:${tracking}`);
    } else {
      git(root, "update-ref", tracking, commit);
    }
    const server = repository();
    const unknown = commitFile(server, "README.md", "# Server only\n");
    seedBare(join(root, ".git", "public.git"), server, unknown);
    expectRefusal(prePush(root, commit), commit, privatePath);
  },
);

it("names_the_push_url_when_the_server_cannot_list_refs", () => {
  // A failed remote lookup could leave the public boundary unverified.
  const root = repository();
  const commit = commitFile(root, "README.md", "# Public\n");
  const url = "ssh://code.example.net/brambleworks/SiteCMD-Local.git";
  const result = prePush(root, commit, {
    url,
    env: localSshEnv(root, join(root, "unavailable.git")),
  });
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain("ls-remote");
  expect(result.stderr).toContain(url);
});

it.each(["", "https::"])("redacts_url_userinfo_when_ref_lookup_fails (%s)", (helper) => {
  // A failed Git lookup exposed URL credentials in its diagnostic.
  const root = repository();
  const commit = commitFile(root, "README.md", "# Public\n");
  const result = prePush(root, commit, {
    url: `${helper}https://fixture-user:fixture-token@code.example.net/brambleworks/SiteCMD-Local.git`,
  });
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain(
    `${helper}https://***@code.example.net/brambleworks/SiteCMD-Local.git`,
  );
  expect(result.stderr).not.toContain("fixture-user");
  expect(result.stderr).not.toContain("fixture-token");
});

it("redacts_the_query_when_ref_lookup_fails", () => {
  // A failed Git lookup exposed a query token in its diagnostic.
  const root = repository();
  const commit = commitFile(root, "README.md", "# Public\n");
  const url = "https::https://fixture-user:fixture-token@code.example.net/repo.git";
  const result = prePush(root, commit, { url: url + "?token=query-secret&other=value" });
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain("https::https://***@code.example.net/repo.git");
  expect(result.stderr).not.toMatch(/fixture-user|fixture-token|query-secret|other=value/);
});

function partialClone(root) {
  const promisor = join(root, ".git", "promisor.git");
  git(root, "init", "--quiet", "--bare", "--initial-branch=main", promisor);
  git(promisor, "config", "uploadpack.allowFilter", "true");
  seedBare(promisor, root, "HEAD");
  const clone = join(root, ".git", "partial");
  git(
    root,
    "clone",
    "--quiet",
    "--no-checkout",
    "--filter=blob:none",
    pathToFileURL(promisor).href,
    clone,
  );
  symlinkSync(join(root, ".git", "public.git"), join(clone, ".git", "public.git"));
  expect(git(clone, "rev-list", "--objects", "--missing=print", "HEAD")).toMatch(
    /^\?[a-f0-9]{40}$/m,
  );
  return clone;
}

it("exempts_already_public_blob_ids_without_fetching_public_blob_contents", () => {
  // Scanning public history fetched every promised blob even though only the IDs were needed.
  const root = repository();
  const contents = "fixture shared with private history\n";
  const base = commitFile(root, "docs/shared.txt", contents);
  const head = commitFile(root, "docs/copied.txt", contents);
  seedBare(join(root, ".git", "public.git"), root, base);
  const privateClone = repository();
  commitFile(privateClone, privatePath, contents);
  const clone = partialClone(root);
  git(clone, "config", "sitecmd.privateClone", privateClone);
  const missing = () => git(clone, "rev-list", "--objects", "--missing=print", base);
  const before = missing();
  expect(before).toContain(`?${git(root, "rev-parse", `${base}:docs/shared.txt`)}`);
  expect(prePush(clone, head)).toMatchObject({ status: 0, stderr: "" });
  expect(missing()).toBe(before);
});

it("passes_server_refs_to_both_revision_walks_on_stdin", () => {
  // Passing server refs as arguments could exceed the operating system's argument limit.
  const root = repository();
  const base = commitFile(root, "README.md", "# Public\n");
  seedBare(join(root, ".git", "public.git"), root, base);
  const privateClone = repository();
  commitFile(privateClone, privatePath, "private\n");
  git(root, "config", "sitecmd.privateClone", privateClone);
  const head = commitFile(root, "docs/open.txt", "fixture\n");
  const trace = join(root, ".git", "git-trace");
  expect(prePush(root, head, { env: { ...localSshEnv(root), GIT_TRACE: trace } })).toMatchObject({
    status: 0,
    stderr: "",
  });
  const walks = readFileSync(trace, "utf8")
    .split("\n")
    .filter((line) => line.includes("built-in: git rev-list"));
  expect(walks).toHaveLength(2);
  for (const walk of walks) {
    expect(walk).toContain("--stdin");
    expect(walk).not.toContain(base);
  }
});

it("refuses_a_private_crate_in_a_blobless_partial_clone", () => {
  // Disabling lazy fetch let missing Cargo blobs bypass the crate scan.
  const root = repository();
  const crate = ["sitecmd", "engine"].join("-");
  const commit = commitFile(root, "Cargo.toml", `[package]\nname = "${crate}"\n`);
  expectRefusal(prePush(partialClone(root), commit), commit, "Cargo.toml");
});

it("fails_closed_when_grep_cannot_read_a_promised_blob", () => {
  // Git grep reported an unreadable blob with the same exit code as a clean scan.
  const root = repository();
  const commit = commitFile(root, "Cargo.toml", '[package]\nname = "public"\n');
  const clone = partialClone(root);
  git(clone, "remote", "set-url", "origin", pathToFileURL(join(root, "unavailable.git")).href);
  const result = prePush(clone, commit);
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain("git grep failed");
});

it("peels_annotated_push_tags_and_refuses_non_commit_tips", () => {
  // Engine code reaching the public repository. Annotated tree and blob tags escaped the tree scan.
  const root = repository();
  const base = commitFile(root, "README.md", "# Public\n");
  const commit = commitFile(root, privatePath, "private\n");
  function pushTag(name, target) {
    git(root, "-c", "tag.gpgSign=false", "tag", "-a", name, "-m", "Fixture", target);
    const ref = `refs/tags/${name}`;
    const oid = git(root, "rev-parse", ref);
    return runCheck(root, ["--pre-push", "public", publicUrl], `${ref} ${oid} ${ref} ${absent}\n`);
  }
  expect(pushTag("clean", base)).toMatchObject({ status: 0, stderr: "" });
  expectRefusal(pushTag("commit", commit), commit, privatePath);
  for (const [name, target] of [
    ["tree", `${commit}^{tree}`],
    ["blob", `${commit}:${privatePath}`],
  ]) {
    const result = pushTag(name, target);
    expect(result.status, result.stderr).toBe(2);
    expect(result.stderr).toMatch(/does not point to a commit/);
    expect(result.stderr).toContain(git(root, "rev-parse", `refs/tags/${name}`));
  }
});

it("refuses_malformed_pre_push_stdin", () => {
  // Engine code reaching the public repository. A malformed ref record with valid hashes was accepted.
  const root = repository();
  const commit = commitFile(root, "README.md", "# Public\n");
  for (const input of ["truncated update\n", `${branch} ${commit} missing-ref ${absent}\n`]) {
    const result = runCheck(root, ["--pre-push", "public", publicUrl], input);
    expect(result.status, result.stderr).toBe(2);
    expect(result.stderr).toContain("Invalid pre-push ref update");
  }
});

it("names_an_unreadable_private_clone_in_the_push_error", () => {
  // Engine code reaching the public repository. A clone error hid which setting and path failed.
  const root = repository();
  const destination = join(root, ".git", "public.git");
  git(root, "remote", "add", "public", publicUrl);
  const clone = join(root, "missing private clone");
  git(root, "config", "sitecmd.privateClone", clone);
  commitFile(root, "README.md", "# Public\n");
  const result = push(root, "public");
  expect(result.status).toBe(1);
  expect(result.stderr).toContain("sitecmd.privateClone");
  expect(result.stderr).toContain(clone);
  expect(git(destination, "rev-list", "--all")).toBe("");
});

it("names_a_private_clone_with_no_engine_paths", () => {
  // An unrelated Git clone silently disabled the configured private blob check.
  const root = repository();
  const clone = repository();
  commitFile(clone, "README.md", "# Unrelated\n");
  git(root, "config", "sitecmd.privateClone", clone);
  const commit = commitFile(root, "README.md", "# Public\n");
  const result = prePush(root, commit);
  expect(result.status, result.stderr).toBe(2);
  expect(result.stderr).toContain("sitecmd.privateClone");
  expect(result.stderr).toContain(clone);
});

it("refuses_a_rust_source_naming_sitecmd_local_engine", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const crate = ["sitecmd", "local", "engine"].join("_");
  const file = `${workspace}/src/core/audit/open.rs`;
  const commit = commitFile(root, file, `use ${crate}::scan;\n`);
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toContain(crate);
});

it("allows_sitecmd_engine_host_in_rust_source", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const file = `${workspace}/src/core/audit/open.rs`;
  const commit = commitFile(root, file, "use sitecmd_engine_host::load;\n");
  expect(prePush(root, commit)).toMatchObject({ status: 0, stderr: "" });
});

it("refuses_private_crate_names_in_uppercase_rust_files", () => {
  // Uppercase Rust extensions skipped the source crate check.
  const root = repository();
  const crate = ["sitecmd", "engine"].join("_");
  const file = "src/open.RS";
  const commit = commitFile(root, file, `use ${crate}::scan;\n`);
  const result = prePush(root, commit);
  expectRefusal(result, commit, file);
  expect(result.stderr).toContain(crate);
});

it("allows_a_deleted_ref_without_reading_the_private_clone", () => {
  // Engine code reaching the public repository.
  const root = repository();
  const commit = commitFile(root, privatePath, "private\n");
  git(root, "config", "sitecmd.privateClone", join(root, "missing"));
  expect(prePush(root, absent, { remote: commit })).toMatchObject({ status: 0, stderr: "" });
});

function legacyPattern(source, flags) {
  return new RegExp(source, flags);
}

it("preserves destination parsing and redaction across Git URL forms", () => {
  // A pattern the regex audit refuses blocked local verification.
  const source = readFileSync(new URL("./check-publication-history.mjs", import.meta.url), "utf8");
  const parser = source.slice(
    source.indexOf("const PRIVATE_PATH"),
    source.indexOf("function git("),
  );
  const current = runInNewContext(
    parser +
      "\n({ transportPrefixLength, parseDestination, isPrivateDestination, redactedDestination })",
  );
  const prefixPattern = legacyPattern(String.raw`^(?:[a-z][a-z\d+.-]*::)+`, "i");
  const networkPattern = legacyPattern(
    String.raw`^(?:https?|git|ssh|git\+ssh|ssh\+git):\/\/(?:[^/?#\s]*@)?(?<host>[^@:/?#\s]+)(?::\d+)?\/(?<path>.*)$`,
    "is",
  );
  const scpPattern = legacyPattern(
    String.raw`^(?:[^@/:\s]+@)?(?<host>[^@:/?#\s]+):(?!\/\/)(?<path>.*)$`,
    "s",
  );
  const privatePath = /^\/*brambleworks\/+SiteCMD-Engine(?:\.git)?\/*$/i;
  const repo = privateRepository + ".git";
  const credentialUrl =
    "https://fixture-user:fixture-token@code.example.net/brambleworks/SiteCMD-Local.git";
  const urls = [
    publicUrl,
    "git@github.com:brambleworks/SiteCMD-Local.git",
    "https://private.example.net/team/engine.git",
    `git@github.com:${repo}`,
    `https://github.com/${repo}`,
    `https://github.com:22/${repo}`,
    `https://github.com:443/${repo}`,
    `ssh://git@github.com/${repo}`,
    `ssh://git@github.com:22/${repo}`,
    `ssh://git@SSH.GITHUB.COM:443/${repo}`,
    `git+ssh://git@github.com/${repo}`,
    `git://github.com/${repo}`,
    "a+1.b-c::https::https://github.com//BRAMBLEWORKS//SiteCMD-ENGINE.GIT//?query#fragment",
    `https://gitlab.com/${repo}`,
    `s3://storage.example.net/${repo}`,
    `https://www.github.com/${repo}`,
    `git@github-brambleworks:${repo}`,
    `https://github.com@code.example.net/${repo}`,
    `ssh::ssh://git@github.com/extra/%2e%2e/${repo}`,
    `git@github.com:extra/../${repo}`,
    `ssh://git@github.com/${repo} whitespace`,
    `ssh+git://git@github.com/extra%3Fquery/../${repo}`,
    `git@github.com:extra%23fragment/../${repo}`,
    `git+ssh://git@github.com/extra%20space/../${repo}`,
    `ssh://[evil.example]@github.com/${repo}`,
    `ssh://git@[evil.example]@github.com/${repo}`,
    `[evil.example]@github.com:${repo}`,
    `git://[evil.example]@github.com/${repo}`,
    `git@[github.com]:${repo}`,
    `git@github.com:${repo}#/../../brambleworks/SiteCMD-Local.git`,
    `ssh://git@github.com/${repo}?/../../brambleworks/SiteCMD-Local.git`,
    `ssh://git@github.com/${repo}?query`,
    `git://github.com/${repo}#fragment`,
    ...["", "https::"].flatMap((transport) =>
      ["\u00a0", "\u1680", "\u2028", "\u202f", "\u3000", "\ufeff"].map(
        (space) => `${transport}https://github.com/${repo}${space}/../SiteCMD-Local.git`,
      ),
    ),
    `ssh://git@github.com/${repo.replaceAll("-", "%2D")}`,
    "a+1.b-c::https::https://github.com//BRAMBLEWORKS/./extra/../SiteCMD%2dEngine.GIT//",
    `https://github.com/extra/../${repo}`,
    `https://github.com/${repo}\t`,
    `https://github.com/${repo}?x=%20`,
    `https://github.com/${repo}#\u007f`,
    "https://github.com/brambleworks/SiteCMD-Local.git",
    "ssh://git@github.com/brambleworks/SiteCMD-Local",
    "ssh://git@ssh.github.com:443/brambleworks/SiteCMD-Local.git/",
    "HTTPS://GITHUB.COM/BRAMBLEWORKS/SITECMD-LOCAL.GIT/",
    "git@github-brambleworks:brambleworks/SiteCMD-Local.git",
    "https://code.example.net/brambleworks/SiteCMD-Local/",
    "git@github.com:/brambleworks/SiteCMD-Local.git",
    "https://github.com/brambleworks/SiteCMD-Local.git?x",
    "https://github.com/brambleworks/SiteCMD-Local.git/info/../",
    "git@github-brambleworks:brambleworks/SiteCMD-Local-archive",
    "https://code.example.net/brambleworks//SiteCMD-Local.git",
    "https://code.example.net/brambleworks/SiteCMD-Local.git//",
    "https://code.example.net/brambleworks/./extra/../SiteCMD-Local.git",
    "https://code.example.net/brambleworks/SiteCMD.git",
    "git@code.example.net:brambleworks/SiteCMD-app.git",
    "ssh://git@code.example.net/brambleworks-co/SiteCMD.git",
    "https::https://github.com/brambleworks/SiteCMD-Local.git",
    "git://code.example.net/brambleworks/SiteCMD%2DLocal.git",
    "ssh://git@github.com/brambleworks-co/SiteCMD-app.git",
    "ssh://git@github.com/someone/SiteCMD-Local.git",
    "ssh://git@github.com/example/another.git",
    `ssh://git@github.com/${privateRepository}-archive.git`,
    `ssh://git@github.com/${repo.replace("-", "%ZZ")}`,
    ...[
      "brambleworks/SiteCMD%2DLocal.git",
      "%62rambleworks/SiteCMD-Local.git",
      "brambleworks%2FSiteCMD-Local.git",
    ].map((path) => `ssh://git@github.com/${path}`),
    "fixture-alias:",
    publicUrl + " ",
    "https://tracking.example.net/brambleworks/SiteCMD-Local.git",
    "ssh://code.example.net/brambleworks/SiteCMD-Local.git",
    credentialUrl,
    "https::" + credentialUrl,
    "https::https://fixture-user:fixture-token@code.example.net/repo.git?token=query-secret&other=value",
    "",
    "x::Y+1.2-3::",
    "9::https://github.com/" + repo,
    "x:::https://github.com/" + repo,
    "HTTP::SSH+GIT://git@GITHUB.COM:00022/" + repo,
    "https://github.com",
    "https://github.com/",
    "https:///" + repo,
    "https://user@:22/" + repo,
    "https://@github.com/" + repo,
    "https://user:token@@github.com:443/" + repo,
    "https://user@github.com@/" + repo,
    "https://user?key@github.com/" + repo,
    "https://user#key@github.com/" + repo,
    "https://user/key@github.com/" + repo,
    "https://github.com:/" + repo,
    "https://github.com:+22/" + repo,
    "https://github.com:22:23/" + repo,
    "https://github.com:２２/" + repo,
    "https://github.com:999999/" + repo,
    "https://github.com/" + repo + "\n",
    "github.com:" + repo,
    "git@github.com:/" + repo,
    "git#tag@github.com:" + repo,
    "github.com:relative@path",
    "github.com:",
    "github.com::",
    "github.com://" + repo,
    "git@:" + repo,
    "@github.com:" + repo,
    "git@@github.com:" + repo,
    "git@github.com:/" + repo + "\n",
    "C:\\src\\engine.git",
    "C:/src/engine.git",
    "C://src/engine.git",
    "\\\\server\\share\\engine.git",
    "file:///tmp/engine.git",
    "file://github.com/" + repo,
    pathToFileURL("/tmp/public.git").href,
    "/tmp/public.git",
    "./public.git",
    "../public.git",
    repo,
  ];

  for (const url of urls) {
    const prefix = prefixPattern.exec(url)?.[0] ?? "";
    const address = url.slice(prefix.length);
    const destination = networkPattern.exec(address)?.groups ?? scpPattern.exec(address)?.groups;
    const http = /^https?:\/\//i.test(address);
    const skips =
      !/[^!-~]|[%[\]]/.test(url) &&
      !!destination &&
      (http || !/[?#]/.test(destination.path)) &&
      ["github.com", "ssh.github.com"].includes(destination.host.toLowerCase()) &&
      privatePath.test(http ? destination.path.split(/[?#]/, 1)[0] : destination.path);
    const redacted =
      prefix +
      address
        .replace(/^([a-z][a-z\d+.-]*:\/\/)[^/?#\s]*@/i, "$1***@")
        .replace(/^[^@/:\s]+@(?=(?:\[[^\]\s]+\]|[^@/:\s]+):)/, "***@")
        .replace(/\?.*/s, "?***");
    expect(
      {
        prefixLength: current.transportPrefixLength(url),
        destination: current.parseDestination(address),
        skips: current.isPrivateDestination(url),
        redacted: current.redactedDestination(url),
      },
      JSON.stringify(url),
    ).toEqual({ prefixLength: prefix.length, destination, skips, redacted });
  }
});
