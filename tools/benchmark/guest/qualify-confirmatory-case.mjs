import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { validateRepositoryConfirmatoryCorpus } from "../lib/repository-corpus.mjs";
import {
  confirmatoryCorpusFilename,
  confirmatoryRegistrationFilename,
  validateRepositoryConfirmatoryRegistration,
} from "../lib/repository-confirmatory-registration.mjs";
import { validateRepositoryReference } from "../lib/repository-reference.mjs";
import {
  validateRepositorySnapshot,
  materializeRepositoryFiles,
} from "../lib/repository-snapshot.mjs";
import { digest } from "../lib/workflow-plan.mjs";
import { confirmatoryQualificationPath } from "./confirmatory-qualification-path.mjs";
import { gradeRepository } from "./repository-grader.mjs";
import { createWorkspace, mountDesktopWorkspace, closeWorkspace } from "./trial-workspace.mjs";

if (process.platform !== "linux" || process.getuid() !== 0)
  throw new Error("Confirmatory qualification requires the isolated guest controller");
const request = JSON.parse(readFileSync(0, "utf8"));
const corpus = validateRepositoryConfirmatoryCorpus(request.corpus);
const pinnedCorpus = JSON.parse(
  readFileSync(new URL(`../cases/${confirmatoryCorpusFilename(corpus.id)}`, import.meta.url)),
);
const pinnedRegistration = JSON.parse(
  readFileSync(new URL(`../cases/${confirmatoryRegistrationFilename(corpus.id)}`, import.meta.url)),
);
if (
  digest(corpus) !== digest(pinnedCorpus) ||
  digest(request.registration) !== digest(pinnedRegistration) ||
  request.eligibility.passed !== true ||
  request.eligibility.modelCalls !== 0
)
  throw new Error("Confirmatory corpus, eligibility, or registration differs from the harness");
validateRepositoryConfirmatoryRegistration(
  request.registration,
  corpus,
  request.eligibility,
  request.referenceScreening,
);
const item = corpus.cases.find((candidate) => candidate.id === request.caseId);
const registered = request.registration.cases.find((candidate) => candidate.id === request.caseId);
if (!item || !registered) throw new Error("Unknown confirmatory case");
const baseline = validateRepositorySnapshot(request.baseline);
const upstream = validateRepositorySnapshot(request.upstream);
const reference =
  item.kind === "negative_control"
    ? validateRepositorySnapshot(request.reference)
    : validateRepositoryReference(request.reference);
if (
  baseline.sha256 !== registered.baselineSha256 ||
  upstream.sha256 !== registered.upstreamSha256 ||
  reference.sha256 !== registered.reference.sha256 ||
  baseline.commit !== item.baselineCommit ||
  upstream.commit !== item.upstreamCommit ||
  !/^[a-f0-9]{40}$/.test(request.product?.commit ?? "") ||
  request.product.cli !== `/opt/sitecmd-benchmark/products/${request.product.commit}/sitecmd_cli` ||
  digest(readFileSync(request.product.cli)) !== request.product.cliSha256
)
  throw new Error("Confirmatory source or product identity differs from its receipt");
if (
  (item.kind === "negative_control" && reference.sha256 !== baseline.sha256) ||
  (item.kind === "repair" &&
    (reference.baselineSha256 !== baseline.sha256 ||
      reference.upstreamSha256 !== upstream.sha256 ||
      JSON.stringify(reference.editableFiles) !== JSON.stringify(item.editableFiles)))
)
  throw new Error("Confirmatory reference scope differs from its registration");

const root = confirmatoryQualificationPath(request.runId, item.id);
mkdirSync(root, { recursive: true, mode: 0o700 });

function scan(snapshot) {
  const files = Object.fromEntries(
    snapshot.files.map((file) => [file.name, Buffer.from(file.base64, "base64")]),
  );
  const id = randomBytes(16).toString("hex");
  const workspace = createWorkspace(id, files);
  let mounted;
  try {
    for (const file of snapshot.files)
      chmodSync(path.join(workspace, file.name), file.mode === "100755" ? 0o755 : 0o644);
    mounted = mountDesktopWorkspace(id, workspace);
    const result = spawnSync(
      "sudo",
      ["-u", "sitecmd", request.product.cli, "audit", mounted.path, "--format", "json"],
      { encoding: "utf8", timeout: 120000, maxBuffer: 16 * 1024 * 1024 },
    );
    const receipt = { exitCode: result.status, raw: result.stdout, stderr: result.stderr };
    if (result.error) receipt.error = result.error.message;
    if (result.status === 0) receipt.report = JSON.parse(result.stdout);
    return receipt;
  } finally {
    try {
      mounted?.close();
    } finally {
      closeWorkspace(workspace);
    }
  }
}

const result = { id: item.id, variants: {} };
for (const [variant, snapshot] of [
  ["baseline", baseline],
  ["reference", reference],
]) {
  const candidate = path.join(root, variant);
  materializeRepositoryFiles(snapshot.files, candidate);
  const gradeItem = {
    id: item.id,
    repository: item.repository.id,
    runtime: item.runtime,
    confirmatory: true,
    entry: registered.entry,
    controlSourceSha256: registered.controlSourceSha256,
    repositoryRuntime: request.repositoryRuntime,
    browserRuntime: request.browserRuntime,
  };
  result.variants[variant] = {
    sourceSha256: snapshot.sha256,
    grades: Array.from({ length: 3 }, () => gradeRepository(gradeItem, candidate)),
    scan: scan(snapshot),
  };
}
const serialized = JSON.stringify(result);
rmSync(root, { recursive: true });
console.log(serialized);
