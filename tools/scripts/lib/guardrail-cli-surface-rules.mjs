const CLI = "apps/desktop/src-tauri/crates/cli/src/main.rs";
const CLI_MANIFEST = "apps/desktop/src-tauri/crates/cli/Cargo.toml";
const APP_MANIFEST = "apps/desktop/src-tauri/Cargo.toml";
const SCAN_TYPES = "apps/desktop/src-tauri/src/core/scanner/types.rs";
const ACTION = ".github/actions/sitecmd-gate";
const SETUP_ACTION = ".github/actions/setup-sitecmd";
const DEV_WRAPPER = "tools/scripts/sitecmd.mjs";
const AUDIT_WORKFLOW = ".github/workflows/app-guardrails.yml";
const POSTGRES_WORKFLOW = ".github/workflows/code-scan-postgres-integration.yml";
const BENCHMARK_SCANNER = "tools/benchmark/lib/scanner.mjs";
const WORKFLOW_GENERATOR = "apps/desktop/src/components/settings/cicd-workflow.ts";
const TAURI_CONFIG = "apps/desktop/src-tauri/tauri.conf.json";
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

/** Every value `--type` accepts, read from the enum that parses it. */
function scanTypeValues(types) {
  const asStr = block(types, "pub fn as_str(self)");
  if (asStr === null) return null;
  return new Set([...asStr.matchAll(/=>\s*"([a-z]+)"/g)].map((match) => match[1]));
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
    APP_MANIFEST,
    SCAN_TYPES,
    DEV_WRAPPER,
    AUDIT_WORKFLOW,
    POSTGRES_WORKFLOW,
    BENCHMARK_SCANNER,
    WORKFLOW_GENERATOR,
    TAURI_CONFIG,
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

  const subcommands = dispatchedSubcommands(read(CLI));
  check(
    subcommands !== null && subcommands.size >= 5,
    `${CLI} main dispatcher could not be read, so no message naming a subcommand can be checked against it. Update guardrail-cli-surface-rules.mjs.`,
  );
  const types = scanTypeValues(read(SCAN_TYPES));
  check(
    types !== null && types.size >= 3,
    `${SCAN_TYPES} ScanType::as_str could not be read, so no message naming a scan type can be checked against it. Update guardrail-cli-surface-rules.mjs.`,
  );
  if (subcommands === null || types === null) return failures;

  const files = [
    ...listFiles("apps/desktop/src-tauri/src/cli", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/crates/cli/src", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/examples", (file) => file.endsWith(".rs")),
    ...listFiles(ACTION, (file) => file.endsWith(".yml") || file.endsWith(".md")),
    ...listFiles(
      SETUP_ACTION,
      (file) => file.endsWith(".yml") || file.endsWith(".md") || file.endsWith(".sh"),
    ),
    DEV_WRAPPER,
    AUDIT_WORKFLOW,
    BENCHMARK_SCANNER,
    WORKFLOW_GENERATOR,
  ];
  check(
    files.length > 2,
    `cli-surface guardrail scanned only ${files.length} files; the enumeration broke. Update guardrail-cli-surface-rules.mjs.`,
  );

  for (const file of files) {
    const source = read(file);
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
      const flag = tokens.indexOf("--type");
      if (flag === -1 || flag + 1 >= tokens.length) continue;
      const value = tokens[flag + 1];
      check(
        types.has(value),
        `${file} names \`--type ${value}\`, which the scan argument parser rejects. The accepted values come from ScanType and are: ${[...types].join(", ")}.`,
      );
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

  const auditWorkflow = read(AUDIT_WORKFLOW);
  check(
    auditWorkflow.includes("crates/cli/Cargo.toml") &&
      auditWorkflow.includes("target/debug/sitecmd_cli audit .") &&
      !auditWorkflow.includes("audit_guardrails") &&
      !auditWorkflow.includes("SITECMD_LICENSE_KEY"),
    `${AUDIT_WORKFLOW} must exercise the shipped free Code Scan CLI, never a deleted or license-gated audit binary.`,
  );
  check(
    auditWorkflow.includes("\n  push:") &&
      auditWorkflow.includes("\n  pull_request:") &&
      auditWorkflow.includes("\n  merge_group:") &&
      auditWorkflow.includes("--fail-on high") &&
      !auditWorkflow.includes("--fail-on critical"),
    `${AUDIT_WORKFLOW} must dogfood the shipped Code Scan CLI automatically on proposed and merged changes at the High severity threshold.`,
  );

  const postgresWorkflow = read(POSTGRES_WORKFLOW);
  check(
    postgresWorkflow.includes("\n  push:") &&
      postgresWorkflow.includes("\n  pull_request:") &&
      postgresWorkflow.includes("\n  schedule:") &&
      postgresWorkflow.includes("SITECMD_POSTGRES_TEST_URL") &&
      postgresWorkflow.includes("postgres_live -- --ignored"),
    `${POSTGRES_WORKFLOW} must automatically exercise supported localhost Postgres inspection on relevant changes and a weekly schedule.`,
  );

  const benchmarkScanner = read(BENCHMARK_SCANNER);
  check(
    benchmarkScanner.includes("apps/desktop/src-tauri/crates/cli/Cargo.toml") &&
      !benchmarkScanner.includes('"--example"') &&
      benchmarkScanner.includes('["audit", projectPath, "--format", "json"]') &&
      benchmarkScanner.includes('["audit", projectPath, "--format", "review"]') &&
      !benchmarkScanner.includes("audit_code_scan"),
    `${BENCHMARK_SCANNER} must benchmark the shipped sitecmd audit command, not a private or retired Code Scan binary.`,
  );

  const setupAction = read(`${SETUP_ACTION}/action.yml`);
  const setupInstaller = read(`${SETUP_ACTION}/install.sh`);
  const gateAction = read(`${ACTION}/action.yml`);
  const generatedWorkflow = read(WORKFLOW_GENERATOR);
  const publicInstaller = read(PUBLIC_INSTALLER);
  const readme = read(README);
  const installerCheck = JSON.parse(read(PACKAGE)).scripts?.["installer:check"];
  const committedPublicKey = read(`${SETUP_ACTION}/updater-public-key.pub`).trim();
  const publicKeyLine = committedPublicKey.split(/\r?\n/).find((line) => line.startsWith("RW"));
  const tauriPublicKey = Buffer.from(
    JSON.parse(read(TAURI_CONFIG)).plugins.updater.pubkey,
    "base64",
  )
    .toString("utf8")
    .trim();
  check(
    committedPublicKey === tauriPublicKey,
    `${SETUP_ACTION}/updater-public-key.pub must exactly match the updater trust root in ${TAURI_CONFIG}.`,
  );
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
      generatedWorkflow.includes(".github/actions/setup-sitecmd@${setupActionRef(") &&
      generatedWorkflow.includes("permissions:\n  contents: read") &&
      !generatedWorkflow.includes("https://sitecmd.com/install.sh") &&
      !read(`${ACTION}/README.md`).includes("@main"),
    "CI workflows and the connected gate must use the signed setup action through an immutable release ref, never a mutable branch or piped remote installer.",
  );

  return failures;
}
