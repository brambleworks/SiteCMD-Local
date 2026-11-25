import { posix as path } from "node:path";
import { CI_WORKFLOW, QUEUE_OR_DISPATCH } from "./ci-workflow-contract.mjs";
import {
  children,
  readJobs,
  runCommand,
  scalar,
  sequence,
  workflowFields,
  workflowJobSteps,
} from "./guardrail-workflow-yaml.mjs";
import { cliDocumentationFailures } from "./cli-documentation.mjs";
import { isPrivateRustPath } from "./guardrail-protocol-contents-rules.mjs";
import { tomlFields } from "./toml-fields.mjs";

const CLI = "apps/desktop/src-tauri/crates/cli/src/main.rs";
const CLI_MANIFEST = "apps/desktop/src-tauri/crates/cli/Cargo.toml";
const RUNTIME_MANIFEST = "apps/desktop/src-tauri/crates/runtime/Cargo.toml";
const APP_MANIFEST = "apps/desktop/src-tauri/Cargo.toml";
export const SCAN_TYPES = new Set(["health", "security", "accessibility", "polish"]);
const ACTION = ".github/actions/sitecmd-gate";
const SETUP_ACTION = ".github/actions/setup-sitecmd";
const DEV_WRAPPER = "tools/scripts/sitecmd.mjs";
const PUBLIC_INSTALLER = "install.sh";
const PACKAGE = "package.json";
const README = "README.md";
const INSTALLER_CHECK =
  "sh -n install.sh && bash -n .github/actions/setup-sitecmd/install.sh && vitest run tools/scripts/installers.test.mjs";

// Return a source block through its matching closing brace.
function block(source, opening) {
  const start = source.indexOf(opening);
  if (start === -1) return null;
  const open = source.indexOf("{", start);
  if (open === -1) return null;
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  return null;
}

// Return every dispatched subcommand and alias.
function dispatchedSubcommands(cli) {
  const dispatcher = block(cli, "match first.as_str()");
  if (dispatcher === null) return null;
  const names = new Set();
  // Dispatcher arms sit at one indent level; nested matches are not commands.
  for (const line of dispatcher.split("\n")) {
    if (!line.startsWith('        "')) continue;
    const arrow = line.indexOf("=>");
    if (arrow === -1) continue;
    const parts = line
      .slice(8, arrow)
      .trim()
      .split("|")
      .map((part) => part.trim());
    if (!/^"(?:[a-z][a-z-]*|--?[a-zA-Z-]+)"$/.test(parts[0])) continue;
    if (!parts.every((part) => /^"[^"|]*"$/.test(part))) continue;
    for (const quoted of parts) {
      names.add(quoted.slice(1, -1));
    }
  }
  return names;
}

export function cliDependencyFailures(
  read,
  exists,
  includeManifest = (file) => !isPrivateRustPath(file),
  additionalManifests = [],
) {
  const failures = [];
  const manifests = new Set([APP_MANIFEST, CLI_MANIFEST, ...additionalManifests]);
  for (const file of manifests) {
    if (!exists(file)) {
      failures.push(`CLI dependency manifest is missing: ${file}.`);
      continue;
    }
    const dependencies = new Set();
    for (const { path: keys, value } of tomlFields(read(file))) {
      const i = keys.findIndex((part) => /^(?:(?:dev|build)-)?dependencies$/.test(part));
      if (i < 0 || keys[i + 1] === undefined) continue;
      dependencies.add(keys[i + 1]);
      if (keys[i + 2] === "package") dependencies.add(value);
      if (keys[i + 2] === "path" && typeof value === "string") {
        const manifest = path.join(path.dirname(file), value, "Cargo.toml");
        if (includeManifest(manifest)) manifests.add(manifest);
      }
    }
    for (const dependency of ["headless_chrome", "hickory-resolver"]) {
      if (dependencies.has(dependency)) failures.push(`${file} must not depend on ${dependency}.`);
    }
  }
  return failures;
}

/**
 * @param {(file: string) => string} read
 * @param {(file: string) => boolean} exists
 * @param {(dir: string, predicate: (file: string) => boolean) => string[]} listFiles
 */
export function cliSurfaceFailures(read, exists, listFiles) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const requiredFiles = [
    CLI,
    CLI_MANIFEST,
    RUNTIME_MANIFEST,
    APP_MANIFEST,
    DEV_WRAPPER,
    CI_WORKFLOW,
    PUBLIC_INSTALLER,
    PACKAGE,
    README,
    `${SETUP_ACTION}/action.yml`,
    `${SETUP_ACTION}/install.sh`,
    `${SETUP_ACTION}/updater-public-key.pub`,
  ];
  if (requiredFiles.some((file) => !exists(file))) {
    return [
      "A required CLI or signed-setup surface is missing; update guardrail-cli-surface-rules.mjs.",
    ];
  }

  failures.push(...cliDependencyFailures(read, exists));

  const subcommands = dispatchedSubcommands(read(CLI));
  check(
    subcommands !== null && subcommands.size >= 5,
    `${CLI} main dispatcher could not be read, so no message naming a subcommand can be checked against it. Update guardrail-cli-surface-rules.mjs.`,
  );
  if (subcommands === null) return failures;

  const commands = new Set(
    [...subcommands].filter((name) => name !== "help" && !name.startsWith("-")),
  );
  failures.push(...cliDocumentationFailures(read, exists, commands));

  const files = [
    ...listFiles("apps/desktop/src-tauri/src/cli", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/crates/cli/src", (file) => file.endsWith(".rs")),
    ...listFiles(ACTION, (file) => file.endsWith(".yml") || file.endsWith(".md")),
    ...listFiles(
      SETUP_ACTION,
      (file) => file.endsWith(".yml") || file.endsWith(".md") || file.endsWith(".sh"),
    ),
    DEV_WRAPPER,
    CI_WORKFLOW,
  ];
  check(
    files.length > 2,
    `cli-surface guardrail scanned only ${files.length} files; the enumeration broke. Update guardrail-cli-surface-rules.mjs.`,
  );

  for (const file of files) {
    const source = read(file).replace(/\\\r?\n/g, " ");
    for (const [, options] of source.matchAll(/\bsitecmd[ \t]+scan\b([^\r\n`]*)/g)) {
      check(
        !/(?:^|\s)--type(?:[\s"'`]|=|$)/.test(options),
        `${file} names \`sitecmd scan --type\`, which the scan argument parser rejects. Use \`--categories\` instead.`,
      );
    }
    for (const [, invocation] of source.matchAll(/`sitecmd ([^`\n]+)`/g)) {
      const tokens = invocation.trim().split(/\s+/);
      const [name] = tokens;
      // Ignore the flag shim and help-text placeholders.
      if (!name.startsWith("-") && !name.startsWith("<")) {
        check(
          subcommands.has(name),
          `${file} tells a reader to run \`sitecmd ${name}\`, which main does not dispatch. A message that names a command the CLI does not have spends the reader's next attempt on a failure.`,
        );
      }
    }
  }

  const wrapper = read(DEV_WRAPPER);
  check(
    wrapper.includes('path.resolve(__dirname, "..", "..")') &&
      wrapper.includes('if (args[0] === "--") args.shift()') &&
      /"crates",\s*"cli",\s*"Cargo.toml"/.test(wrapper) &&
      !wrapper.includes('"--example"') &&
      !wrapper.includes("audit_guardrails"),
    `${DEV_WRAPPER} must accept pnpm's separator, resolve the repository root, and dispatch through the shipped headless CLI package.`,
  );

  const cliManifest = read(CLI_MANIFEST);
  const appManifest = read(APP_MANIFEST);
  check(
    /sitecmd-runtime\s*=\s*\{[^}\n]*path\s*=\s*"\.\.\/runtime"[^}\n]*\}/.test(cliManifest) &&
      !/^(?:app_lib|tauri|sitecmd)\s*=/m.test(cliManifest) &&
      appManifest.includes('"crates/cli"') &&
      appManifest.includes('"crates/runtime"'),
    `${CLI_MANIFEST} must remain a Tauri-free workspace package that depends on the shared sitecmd-runtime.`,
  );

  if (exists(".github/ci-job-visibility.json")) {
    const ciJobs = readJobs(workflowFields(read(CI_WORKFLOW)));
    const ciSteps = workflowJobSteps(ciJobs);
    const audit = ciJobs.get("code-scan-audit") ?? new Map();
    const auditSteps = ciSteps.get("code-scan-audit") ?? [];
    const auditCommand = auditSteps.find((step) => runCommand(step)?.includes('"$cli" audit .'));
    const auditRun = runCommand(auditCommand ?? new Map()) ?? "";
    const releaseSteps = ciSteps.get("cli-release-smoke") ?? [];
    // The inventory pins the engine build command in this job.
    const localEngineBuild = releaseSteps.findIndex(
      (step) => scalar(step.get("name")) === "Build the local engine" && !step.has("if"),
    );
    const releaseCliBuild = releaseSteps.findIndex(
      (step) =>
        runCommand(step) === "cargo build --locked --release -p sitecmd-cli" && !step.has("if"),
    );
    const auditConfig = JSON.stringify([[...audit], ...auditSteps.map((step) => [...step])]);
    check(
      auditRun.includes(
        'cli="$GITHUB_WORKSPACE/apps/desktop/src-tauri/target/release/sitecmd_cli"',
      ) && !/audit_guardrails|SITECMD_LICENSE_KEY/.test(auditConfig),
      "ci.yml must exercise the shipped free Code Scan CLI, never a deleted or license-gated audit binary.",
    );
    check(
      scalar(audit.get("if")) === QUEUE_OR_DISPATCH &&
        sequence(audit.get("needs")).includes("cli-release-smoke") &&
        localEngineBuild >= 0 &&
        localEngineBuild < releaseCliBuild &&
        !auditCommand?.has("if") &&
        auditRun.includes("--fail-on high") &&
        !auditRun.includes("--fail-on critical"),
      "ci.yml must dogfood the shipped Code Scan CLI with the current engine at the High severity threshold in the merge queue.",
    );

    const postgres = ciJobs.get("postgres-engine-tests") ?? new Map();
    check(
      scalar(postgres.get("if")) === QUEUE_OR_DISPATCH &&
        children(postgres.get("env")).has("SITECMD_POSTGRES_TEST_URL") &&
        ciSteps
          .get("postgres-engine-tests")
          ?.some(
            (step) =>
              !step.has("if") &&
              runCommand(step)?.includes("-p sitecmd-runtime postgres_live -- --ignored"),
          ),
      "ci.yml must automatically exercise supported localhost Postgres inspection in the merge queue.",
    );
  }

  const setupAction = read(`${SETUP_ACTION}/action.yml`);
  const setupInstaller = read(`${SETUP_ACTION}/install.sh`);
  const gateAction = read(`${ACTION}/action.yml`);
  const publicInstaller = read(PUBLIC_INSTALLER);
  const readme = read(README);
  const installerCheck = JSON.parse(read(PACKAGE)).scripts?.["installer:check"];
  const committedPublicKey = read(`${SETUP_ACTION}/updater-public-key.pub`).trim();
  const publicKeyLine = committedPublicKey.split(/\r?\n/).find((line) => line.startsWith("RW"));
  check(
    setupInstaller.includes("$archive.sig") &&
      setupInstaller.includes("minisign -Vm") &&
      setupInstaller.includes('"sitecmd $version"') &&
      setupAction.includes("sudo apt-get install -y --no-install-recommends minisign") &&
      !setupInstaller.includes("latest") &&
      !setupInstaller.includes("| sh"),
    `${SETUP_ACTION} must install an exact CLI release only after updater-key signature and binary-version verification.`,
  );
  check(
    installerCheck === INSTALLER_CHECK,
    `${PACKAGE} installer gate must parse both scripts and run the behavior suite.`,
  );
  check(
    publicKeyLine &&
      publicInstaller.includes(`MINISIGN_PUBLIC_KEY="${publicKeyLine}"`) &&
      publicInstaller.includes("$archive.sig") &&
      publicInstaller.includes("$archive.sha256") &&
      publicInstaller.includes("minisign -Vm") &&
      publicInstaller.includes('"sitecmd $version"') &&
      readme.includes("[maintained in this repository](install.sh)") &&
      readme.includes("sh sitecmd-install.sh"),
    `${PUBLIC_INSTALLER} must remain a public, reviewable installer bound to the updater trust root, with an inspect-before-run path in ${README}.`,
  );
  const installerKey = /MINISIGN_PUBLIC_KEY="([^"\n]+)"/.exec(publicInstaller)?.[1];
  const readmeVerifyCommand = `minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P ${installerKey}`;
  check(
    installerKey !== undefined &&
      readme.includes(`\n${installerKey}\n`) &&
      readme.includes(readmeVerifyCommand),
    `${README} must print the updater public key exactly as ${PUBLIC_INSTALLER} sets MINISIGN_PUBLIC_KEY, in the code block and the minisign -P argument; whoever verifies a download has to trust one key, not two.`,
  );
  check(
    gateAction.includes('"$GITHUB_ACTION_PATH/../setup-sitecmd/install.sh"') &&
      !gateAction.includes("https://sitecmd.com/install.sh") &&
      !read(`${ACTION}/README.md`).includes("@main"),
    "CI workflows and the connected gate must use the signed setup action through an immutable release ref, never a mutable branch or piped remote installer.",
  );

  return failures;
}
