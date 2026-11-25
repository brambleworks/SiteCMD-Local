import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it } from "vitest";

import {
  children,
  runCommand,
  scalar,
  workflowFields,
  workflowSteps,
} from "./lib/guardrail-workflow-yaml.mjs";

const ROOT = fileURLToPath(new URL("../..", import.meta.url));
const read = (file) => fs.readFileSync(path.join(ROOT, file), "utf8");

describe("sitecmd-gate action inputs", () => {
  const action = read(".github/actions/sitecmd-gate/action.yml");
  it("accepts fail-on and keeps threshold as a deprecated alias", () => {
    expect(action).toMatch(/^ {2}fail-on:\n {4}description:/m);
    expect(action).toMatch(
      /^ {2}threshold:\n {4}description: >-\n {6}Deprecated alias of fail-on/m,
    );
    expect(action).toMatch(/--fail-on "\$SITECMD_FAIL_ON"/);
    expect(action).not.toMatch(/--threshold "\$SITECMD_THRESHOLD"/);
  });
});

/** The gate step's shell, dedented out of the composite action. */
function gateStepScript(action) {
  const lines = action.split("\n");
  const step = lines.findIndex((line) => line.trim() === "id: gate");
  const run = lines.findIndex((line, index) => index > step && line.trim() === "run: |");
  const body = [];
  for (const line of lines.slice(run + 1)) {
    if (line.trim() !== "" && !line.startsWith("        ")) break;
    body.push(line.slice(8));
  }
  return body.join("\n");
}

// Stands in for the CLI: prints what it would, writes the verdict file the
// action names, and exits as the real command does for each outcome.
const STUB_SITECMD = `#!/bin/sh
printf '%s\\n' "$@" > "$RUNNER_TEMP/sitecmd-arguments"
outputs=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "--outputs" ]; then outputs="$2"; shift; fi
  shift
done
case "$STUB_OUTCOME" in
  pass)
    echo "PASS: 0 new finding(s), 0 at or above high, 0 warned"
    printf 'verdict=pass\\nnew=0\\n' > "$outputs"
    exit 0 ;;
  fail)
    echo "FAIL: 2 new finding(s), 2 at or above high, 0 warned"
    printf 'verdict=fail\\nnew=2\\n' > "$outputs"
    exit 1 ;;
  inactive)
    echo "SiteCMD says this account is inactive, so the gate graded nothing. Renew it from the dashboard to resume."
    echo "::notice title=SiteCMD::SiteCMD says this account is inactive, so the gate graded nothing. Renew it from the dashboard to resume."
    printf 'verdict=inactive\\nnew=0\\n' > "$outputs"
    exit 0 ;;
  no-verdict)
    echo "PASS: 0 new finding(s), 0 at or above high, 0 warned"
    exit 0 ;;
  unknown-verdict)
    echo "PASS: 0 new finding(s), 0 at or above high, 0 warned"
    printf 'verdict=maybe\\nnew=0\\n' > "$outputs"
    exit 0 ;;
  *)
    echo "Error: the connected service could not be reached" >&2
    exit 2 ;;
esac
`;

describe("sitecmd-gate action verdict", () => {
  const roots = [];
  afterEach(() => {
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });

  function runGateStep(outcome, { strict = "false" } = {}) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-gate-action-"));
    roots.push(root);
    const bin = path.join(root, "bin");
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "sitecmd"), STUB_SITECMD, { mode: 0o755 });
    const githubOutput = path.join(root, "github-output");
    const stepSummary = path.join(root, "step-summary");
    fs.writeFileSync(githubOutput, "");
    fs.writeFileSync(stepSummary, "");
    const result = spawnSync(
      "bash",
      ["-c", gateStepScript(read(".github/actions/sitecmd-gate/action.yml"))],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          PATH: `${bin}${path.delimiter}${process.env.PATH}`,
          RUNNER_TEMP: root,
          GITHUB_OUTPUT: githubOutput,
          GITHUB_STEP_SUMMARY: stepSummary,
          SITECMD_CI_TOKEN: "sitecmd_ci_test",
          SITECMD_CONNECTION_PASSPHRASE: "correct horse battery staple",
          SITECMD_CONNECTION_EXPORT: "{}",
          SITECMD_DB_PATH: path.join(root, "sitecmd.db"),
          SITECMD_STRICT: strict,
          SITECMD_FAIL_ON: "high",
          STUB_OUTCOME: outcome,
        },
      },
    );
    const argumentsFile = path.join(root, "sitecmd-arguments");
    return {
      arguments: fs.existsSync(argumentsFile)
        ? fs.readFileSync(argumentsFile, "utf8").trimEnd().split("\n")
        : [],
      status: result.status,
      stdout: result.stdout,
      outputs: fs.readFileSync(githubOutput, "utf8"),
      summary: fs.readFileSync(stepSummary, "utf8"),
    };
  }

  it("reports an inactive account as its own verdict, never as a pass", () => {
    const run = runGateStep("inactive");

    expect(run.status).toBe(0);
    expect(run.outputs).toBe("verdict=inactive\nnew=0\n");
    expect(run.summary).toBe(
      "### SiteCMD gate: inactive\n\nSiteCMD says this account is inactive, so the gate graded nothing.\n",
    );
    expect(run.summary).not.toContain("::notice");
    // The annotation still reaches the runner through the step's own log.
    expect(run.stdout).toContain("::notice title=SiteCMD::");
  });

  it("reads a pass and a block from the CLI's verdict file", () => {
    const pass = runGateStep("pass");
    expect(pass.status).toBe(0);
    expect(pass.outputs).toBe("verdict=pass\nnew=0\n");
    expect(pass.summary).toContain("### SiteCMD gate: pass");
    expect(pass.summary).toContain("PASS: 0 new finding(s)");

    const fail = runGateStep("fail");
    expect(fail.status).toBe(1);
    expect(fail.outputs).toBe("verdict=fail\nnew=2\n");
    expect(fail.summary).toContain("### SiteCMD gate: fail");
  });

  it("names no verdict when the gate could not run", () => {
    const broken = runGateStep("broken");

    expect(broken.status).toBe(2);
    expect(broken.outputs).toBe("");
    expect(broken.stdout).toContain("::error::The SiteCMD gate could not run (exit 2).");
  });

  it("passes --strict only when the workflow asks for it", () => {
    const strict = runGateStep("pass", { strict: "true" });
    expect(strict.status).toBe(0);
    expect(strict.arguments).toContain("--strict");

    const lenient = runGateStep("pass");
    expect(lenient.status).toBe(0);
    expect(lenient.arguments).not.toContain("--strict");
    expect(lenient.arguments).toContain("--outputs");
  });

  it("refuses a run whose verdict file is missing or names no known verdict", () => {
    for (const outcome of ["no-verdict", "unknown-verdict"]) {
      const run = runGateStep(outcome);

      expect(run.status, outcome).toBe(2);
      expect(run.stdout, outcome).toContain("::error::The SiteCMD gate named no verdict.");
      expect(run.outputs, outcome).toBe("");
      expect(run.summary, outcome).toBe("");
    }
  });
});

it.each([
  ["", true],
  ["custom directory with spaces", true],
  ["custom\nextra-path", false],
  ["custom\rpath", false],
])("exports only the selected install directory for %j", (installDir, allowed) => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-path-"));
  try {
    const githubPath = path.join(root, "github-path");
    fs.writeFileSync(githubPath, "existing\n");
    const result = spawnSync(
      "bash",
      [path.join(ROOT, ".github/actions/setup-sitecmd/add-path.sh")],
      {
        encoding: "utf8",
        env: {
          ...process.env,
          RUNNER_TEMP: root,
          GITHUB_PATH: githubPath,
          SITECMD_INSTALL_DIR: installDir,
        },
      },
    );
    expect(result.status).toBe(allowed ? 0 : 2);
    expect(fs.readFileSync(githubPath, "utf8")).toBe(
      allowed ? `existing\n${installDir || path.join(root, "sitecmd-bin")}\n` : "existing\n",
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

it("the gate installer adds its selected CLI directory to PATH", () => {
  const runs = children(
    workflowFields(read(".github/actions/sitecmd-gate/action.yml")).get("runs"),
  );
  const installStep = workflowSteps(runs.get("steps")).find(
    (step) => scalar(step.get("name")) === "Install the SiteCMD CLI",
  );
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "sitecmd-gate-install-"));
  try {
    const gateDir = path.join(root, "sitecmd-gate");
    const setupDir = path.join(root, "setup-sitecmd");
    const bin = path.join(root, "bin");
    for (const directory of [gateDir, setupDir, bin]) fs.mkdirSync(directory);
    fs.writeFileSync(path.join(bin, "minisign"), "#!/bin/sh\n", { mode: 0o755 });
    fs.writeFileSync(
      path.join(setupDir, "install.sh"),
      '#!/bin/sh\nprintf "%s\\n" "$SITECMD_INSTALL_DIR" > "$INSTALL_LOG"\n',
      { mode: 0o755 },
    );
    fs.writeFileSync(
      path.join(setupDir, "add-path.sh"),
      '#!/bin/sh\nprintf "%s\\n" "$SITECMD_INSTALL_DIR" > "$ADD_PATH_LOG"\nexec bash "$REAL_ADD_PATH"\n',
    );
    const runnerTemp = path.join(root, "runner temp");
    const installDir = scalar(children(installStep.get("env")).get("SITECMD_INSTALL_DIR")).replace(
      "${{ runner.temp }}",
      runnerTemp,
    );
    const githubPath = path.join(root, "github-path");
    const installLog = path.join(root, "install-log");
    const addPathLog = path.join(root, "add-path-log");
    fs.writeFileSync(githubPath, "");
    fs.writeFileSync(addPathLog, "");
    const result = spawnSync("bash", ["-c", runCommand(installStep)], {
      encoding: "utf8",
      env: {
        ...process.env,
        PATH: bin + path.delimiter + process.env.PATH,
        RUNNER_TEMP: runnerTemp,
        GITHUB_ACTION_PATH: gateDir,
        GITHUB_PATH: githubPath,
        SITECMD_INSTALL_DIR: installDir,
        INSTALL_LOG: installLog,
        ADD_PATH_LOG: addPathLog,
        REAL_ADD_PATH: path.join(ROOT, ".github/actions/setup-sitecmd/add-path.sh"),
      },
    });
    expect(result.status, result.stderr).toBe(0);
    expect(installDir).toBe(path.join(runnerTemp, "sitecmd-bin"));
    expect(fs.readFileSync(installLog, "utf8")).toBe(installDir + "\n");
    expect(fs.readFileSync(addPathLog, "utf8")).toBe(installDir + "\n");
    expect(fs.readFileSync(githubPath, "utf8")).toBe(installDir + "\n");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
