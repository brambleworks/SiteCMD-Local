import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { digest } from "./lib/workflow-plan.mjs";
import { evaluateQuota, verifyQuotaUsageContinuity } from "./lib/workflow-quota.mjs";
import { validateRunnableStudy } from "./lib/workflow-runnable-study.mjs";
import { loadPlan, loadResults } from "./lib/workflow-store.mjs";
import { exportGuestTrial } from "./lib/vm-trial-export.mjs";
import { deployHarness } from "./lib/vm-harness.mjs";
import { guestCommand, guestProcess } from "./lib/vm-guest.mjs";
import { verifyContinuation } from "./lib/workflow-continuation.mjs";
import { loadTrialSource } from "./lib/trial-source.mjs";
import { buildTrialItem } from "./lib/trial-item.mjs";
import { verifyControllerAmendment } from "./lib/workflow-controller-amendment.mjs";

const supplied = process.argv[2];
if (!supplied) throw new Error("Usage: run-next.mjs RUN_DIRECTORY");
const run = path.resolve(supplied);
const plan = loadPlan(run);
validateRunnableStudy(plan.study);
verifyContinuation(run, plan);
const recorded = new Set(loadResults(run, plan).map((record) => record.trialId));
const assignment = plan.assignments.find((item) => !recorded.has(item.id));
if (!assignment) {
  console.log("All assignments are recorded; independent review is next.");
  process.exit(0);
}
const baseline = JSON.parse(readFileSync(path.join(run, "quota-baseline.json")));
const currentPath = path.join(run, "quota-current.json");
const current = JSON.parse(readFileSync(currentPath));
const provider = plan.study.configurations.find(
  (entry) => entry.id === assignment.configuration,
).agent;
const quota = evaluateQuota(baseline, current, plan.study.billing, Date.now(), provider);
if (!quota.quotaAllowed) throw new Error(quota.blockers.join("; "));
const baselineHashFile = path.join(run, "quota-baseline.sha256");
// "wx" refuses an existing receipt, so the compare below is the real check.
try {
  writeFileSync(baselineHashFile, digest(baseline), { flag: "wx", mode: 0o600 });
} catch (error) {
  if (error.code !== "EEXIST") throw error;
}
if (readFileSync(baselineHashFile, "utf8") !== digest(baseline))
  throw new Error("The original quota baseline changed; do not rebase the approved allowance");
const harness = deployHarness();
const controllerAmendment =
  harness.id === plan.study.runnerSha256 ? null : verifyControllerAmendment(run, plan, harness);
const corpus = JSON.parse(readFileSync(path.join(run, "inputs", "corpus.json")));
if (digest(corpus) !== plan.study.corpusSha256) throw new Error("Frozen corpus changed");
const item = corpus.find((item) => item.id === assignment.task);
const product = JSON.parse(readFileSync(path.join(run, "inputs", "product.json")));
if (digest(product) !== plan.study.productSha256) throw new Error("Frozen product receipt changed");
const report = readFileSync(path.join(run, "inputs", `${assignment.task}-report.json`), "utf8");
const task = plan.study.tasks.find((task) => task.id === assignment.task);
loadTrialSource(item.baselineFiles, task);
if (digest(report) !== task.reportSha256) throw new Error("Frozen input changed");
for (const [field, input] of [
  ["runtimeSha256", "repositoryRuntime"],
  ["browserRuntimeSha256", "browserRuntime"],
])
  if (task[field] !== undefined && digest(item[input]) !== task[field])
    throw new Error("Frozen repository runtime changed");
console.log(
  `Running ${assignment.task}, ${assignment.configuration}, ${assignment.arm}. Update quota-current.json from real readings before it becomes five minutes old.`,
);
const child = guestProcess(
  [
    "sudo",
    "flock",
    "-n",
    "/run/sitecmd-benchmark-execution.lock",
    "node",
    `${harness.directory}/run-trial.mjs`,
  ],
  JSON.stringify({
    plan,
    assignment,
    item: buildTrialItem(item, task),
    files: item.baselineFiles,
    product,
    report,
    baseline,
    current,
    controllerAmendment,
  }),
);
let output = "";
child.stdout.on("data", (chunk) => {
  output += chunk;
  if (output.length > 1024 * 1024) child.kill("SIGTERM");
});
child.stderr.pipe(process.stderr);
let previousSnapshot = current;
let previous = digest(previousSnapshot);
let syncing = false;
const timer = setInterval(() => {
  if (syncing) return;
  syncing = true;
  try {
    const snapshot = JSON.parse(readFileSync(currentPath));
    if (digest(snapshot) !== previous) {
      evaluateQuota(baseline, snapshot, plan.study.billing, Date.now(), provider);
      verifyQuotaUsageContinuity(baseline, previousSnapshot, snapshot);
      guestCommand(["sudo", "node", `${harness.directory}/update-quota.mjs`], {
        input: JSON.stringify({
          directory: `/srv/sitecmd-benchmark/trials/${assignment.id}`,
          snapshot,
          billing: plan.study.billing,
          provider,
        }),
        capture: true,
      });
      previousSnapshot = snapshot;
      previous = digest(snapshot);
    }
  } catch (error) {
    console.error(`Quota update not accepted: ${error.message}`);
  } finally {
    syncing = false;
  }
}, 2000);
const interrupt = () => {
  try {
    guestCommand(["sudo", "node", `${harness.directory}/cancel-trial.mjs`, assignment.id], {
      capture: true,
    });
  } catch (error) {
    console.error(
      `Cancellation could not be confirmed: ${error.message}. Stop the dedicated VM if guest control is unavailable.`,
    );
  }
};
process.once("SIGINT", interrupt);
process.once("SIGTERM", interrupt);
const exitCode = await new Promise((resolve, reject) => {
  child.once("error", reject);
  child.once("close", resolve);
}).finally(() => {
  clearInterval(timer);
  process.removeListener("SIGINT", interrupt);
  process.removeListener("SIGTERM", interrupt);
});
if (exitCode !== 0)
  throw new Error(
    `Guest trial stopped with status ${exitCode}; retain its private evidence before retrying`,
  );
const outcome = JSON.parse(output);
exportGuestTrial(run, plan, assignment, harness);
console.log(
  `Recorded ${assignment.id}: ${outcome.record.status}. Independent reviews remain pending.`,
);
if (outcome.record.status !== "completed") process.exitCode = 2;
