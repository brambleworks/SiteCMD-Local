import { posix } from "node:path";
import { CI_WORKFLOW } from "./ci-workflow-contract.mjs";
import { isRustCache } from "./guardrail-rust-cache-env.mjs";
import { children, runCommand, scalar } from "./guardrail-workflow-yaml.mjs";

const GUARDRAIL_TEST_SCRIPTS = new Set(["guardrails:repo:test", "private:guardrails:test"]);
const RUST_NODE_SCRIPTS = new Set([
  "audit-rust-deps.mjs",
  "build-checks-wasm.mjs",
  "build-connect-sets.mjs",
  "build-local-engine.mjs",
  "build-local-engine.node-test.mjs",
  "build-scorer-wasm.mjs",
  "build-standin.mjs",
  "build-wasm-artifact.mjs",
  "build_checks.mjs",
  "check-rust-dependency-policy.mjs",
  "check-rust-toolchain.mjs",
  "cli-smoke.mjs",
  "cli-workspace.test.mjs",
  "export-open-tree.mjs",
  "export-open-tree.test.mjs",
  "generate-third-party-artifacts.mjs",
  "generate-wasm-licenses.mjs",
  "guardrail-engine-host-rules.test.mjs",
  "sitecmd.mjs",
  "verify-characterization.mjs",
  "verify-engine.mjs",
  "verify-push.mjs",
]);
const RUST_COMMANDS = new Set(["cargo", "rustc"]);
const JS_COMMANDS = new Set(["node", "npm", "pnpm", "npx"]);
const COMMAND_PREFIXES = new Set(["!", "command", "do", "elif", "else", "exec", "if", "then"]);
const PACKAGE_OPTIONS_WITH_VALUE = new Set([
  "--dir",
  "-C",
  "--filter",
  "--filter-prod",
  "-F",
  "--package",
  "-p",
  "--prefix",
  "--workspace",
  "-w",
]);
const CARGO_WORKSPACE = "apps/desktop/src-tauri";
const PINNED_RUST_SETUP =
  "rustc --version\nrustup default \"$(rustup show active-toolchain | cut -d ' ' -f 1)\"";

// Splits text on separator characters outside quotes and backslash escapes,
// keeping the quotes. A loop instead of a regex keeps audit:regex clean.
function splitOutsideQuotes(text, isSeparator) {
  const tokens = [];
  let token = "";
  let quote = "";
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quote === "" && isSeparator(char)) {
      if (token) tokens.push(token);
      token = "";
      continue;
    }
    token += char;
    if (char === "\\" && quote !== "'" && index + 1 < text.length) {
      index += 1;
      token += text[index];
    } else if (quote === "" && (char === "'" || char === '"')) quote = char;
    else if (char === quote) quote = "";
  }
  if (token) tokens.push(token);
  return tokens;
}

export function commandWords(source) {
  const segments = source
    .split(/\$\(|[`\n]/)
    .flatMap((line) => splitOutsideQuotes(line, (char) => ";&|".includes(char)));
  return segments.map((segment) => {
    const words = splitOutsideQuotes(
      segment
        .trim()
        .replace(/^-\s+run:/, "run:")
        .replace(/^run:\s+/, ""),
      (char) => /\s/.test(char),
    );
    const commandIndex = words.findIndex(
      (word) => !/^[a-z_]\w*=/i.test(word) && !COMMAND_PREFIXES.has(word),
    );
    if (commandIndex === -1) return [];
    if (words[commandIndex] !== "env") return words.slice(commandIndex);
    const wrapped = words.slice(commandIndex + 1);
    const executable = wrapped.findIndex((word) => !/^(?:[a-z_]\w*=|-)/i.test(word));
    return executable === -1 ? [] : wrapped.slice(executable);
  });
}

function packageOperands(args) {
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--") return args.slice(index + 1);
    if (!arg.startsWith("-")) return args.slice(index);
    if (PACKAGE_OPTIONS_WITH_VALUE.has(arg)) index += 1;
  }
  return [];
}

export function packageCommand([executable, ...args]) {
  const command = posix.basename(executable ?? "");
  if (!JS_COMMANDS.has(command) || command === "node") return {};
  const operands = packageOperands(args);
  if (command === "npx") return { wrapped: operands };
  const [mode, ...rest] = operands;
  if (mode === "exec" || mode === "dlx") return { wrapped: packageOperands(rest) };
  const [script, ...scriptArgs] =
    mode === "run" || mode === "run-script" ? packageOperands(rest) : operands;
  return { script, scriptArgs };
}

function runsRust([executable, ...args], scripts, seen = new Set()) {
  if (!executable) return false;
  const command = posix.basename(executable);
  if (RUST_COMMANDS.has(command)) return true;
  if (command === "node") {
    return args.some((arg) =>
      RUST_NODE_SCRIPTS.has(posix.basename(arg.replace(/^(['"])(.*)\1$/, "$2"))),
    );
  }
  const { wrapped, script: task } = packageCommand([executable, ...args]);
  if (wrapped) return runsRust(wrapped, scripts, seen);
  if (
    GUARDRAIL_TEST_SCRIPTS.has(task) ||
    task === "sitecmd" ||
    /^verify:push(?::all)?$|(?:^|[:-])rust(?:$|[:-])/.test(task ?? "")
  )
    return true;
  if (!task || !Object.hasOwn(scripts, task) || seen.has(task)) return false;
  seen.add(task);
  return commandWords(scripts[task]).some((words) => runsRust(words, scripts, seen));
}

function requiredStep(step) {
  return !step.has("if") && !step.has("continue-on-error");
}

function cargoWorkspaceStep(step) {
  return requiredStep(step) && scalar(step.get("working-directory")) === CARGO_WORKSPACE;
}

export function checkGuardrailTestSetup(file, steps, failures) {
  for (const [job, jobSteps] of steps) {
    const test = jobSteps.findIndex((step) =>
      commandWords(runCommand(step) ?? "").some((words) =>
        GUARDRAIL_TEST_SCRIPTS.has(packageCommand(words).script),
      ),
    );
    if (test === -1) continue;
    const setup = jobSteps.slice(0, test).filter(cargoWorkspaceStep).map(runCommand);
    const rust = setup.indexOf(PINNED_RUST_SETUP);
    const prefix = `${file} job ${job} must`;
    const suffix = "before running guardrail tests.";
    if (rust === -1) {
      failures.push(`${prefix} install the pinned Rust toolchain ${suffix}`);
    }
    if (!setup.slice(rust + 1).includes("cargo fetch --locked")) {
      failures.push(`${prefix} run cargo fetch --locked for ${CARGO_WORKSPACE} ${suffix}`);
    }
  }
}

export function checkLockedCargoFetch(steps, scripts, failures) {
  for (const [job, jobSteps] of steps) {
    const commands = jobSteps.map((step) => commandWords(runCommand(step) ?? ""));
    const rust = jobSteps.findIndex(
      (step) => cargoWorkspaceStep(step) && runCommand(step) === PINNED_RUST_SETUP,
    );
    const cache = jobSteps.findLastIndex(isRustCache);
    if (
      rust === -1 &&
      cache === -1 &&
      !commands.some((commands) => commands.some((words) => runsRust(words, scripts)))
    )
      continue;
    if (rust === -1) {
      failures.push(
        `${CI_WORKFLOW} job ${job} must install the pinned Rust toolchain before using Rust.`,
      );
    }
    const firstWork = commands.findIndex(
      (words, index) =>
        index !== rust &&
        words.some(([executable]) => {
          const command = executable && posix.basename(executable);
          return RUST_COMMANDS.has(command) || JS_COMMANDS.has(command);
        }),
    );
    const fetch = jobSteps[firstWork];
    if (
      !fetch ||
      firstWork <= Math.max(rust, cache) ||
      runCommand(fetch) !== "cargo fetch --locked" ||
      !cargoWorkspaceStep(fetch)
    ) {
      failures.push(
        `${CI_WORKFLOW} job ${job} must run cargo fetch --locked for ${CARGO_WORKSPACE} after toolchain and Rust cache setup and before other Cargo or Node commands.`,
      );
    }
  }
}

export function conditionOf(fields) {
  return scalar(fields.get("if"))?.replace(/^\$\{\{\s*(.*?)\s*\}\}$/, "$1") ?? null;
}

export function checkActionPins(file, jobs, steps, failures) {
  const mappings = new Set([...jobs.values(), ...[...steps.values()].flat()]);
  for (const mapping of mappings) {
    const uses = mapping.get("uses");
    if (!uses) continue;
    const ref = scalar(uses);
    if (ref.startsWith("./")) continue;
    const action = ref.split("@", 1)[0];
    if (/^dtolnay\/rust-toolchain(?:\/|$)/i.test(action)) {
      failures.push(file + " must install Rust with rustup instead of dtolnay/rust-toolchain.");
    }
    if (!/@[a-f0-9]{40}$/.test(ref) || !/^v\d+\.\d+\.\d+$/.test(uses.comment ?? "")) {
      failures.push(
        file + " must pin " + action + " to a commit with an exact vX.Y.Z release tag comment.",
      );
    }
  }
}

export function checkToolPins(file, steps, failures) {
  for (const [job, jobSteps] of steps) {
    for (const step of jobSteps) {
      if (!/^taiki-e\/install-action@/i.test(scalar(step.get("uses")) ?? "")) continue;
      const tools = scalar(children(step.get("with")).get("tool")) ?? "";
      for (const tool of tools.trim().split(/[\s,]+/)) {
        if (/^[\w-]+@\d+\.\d+\.\d+$/.test(tool)) continue;
        failures.push(
          `${file} job ${job} must pin each taiki-e/install-action tool to an exact version: ${tool || "(missing tool)"}.`,
        );
      }
    }
  }
}
