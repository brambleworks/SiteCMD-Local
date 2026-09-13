export const WORKFLOW_ARMS = ["normal", "report", "mcp"];
export const TRIAL_STATUSES = [
  "completed",
  "timeout",
  "agent_error",
  "product_error",
  "infrastructure_error",
];
const SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;

export function requireCondition(value, message) {
  if (!value) throw new Error(message);
}

export function requireNumber(value, label, { positive = false, integer = false } = {}) {
  requireCondition(
    typeof value === "number" &&
      Number.isFinite(value) &&
      (positive ? value > 0 : value >= 0) &&
      (!integer || Number.isSafeInteger(value)),
    `${label} must be a ${positive ? "positive" : "non-negative"}${integer ? " integer" : " number"}`,
  );
}

export function requireText(value, label) {
  requireCondition(typeof value === "string" && value.trim().length > 0, `${label} is required`);
}

export function requireHash(value, label) {
  requireCondition(
    typeof value === "string" && SHA256.test(value),
    `${label} must be a SHA-256 digest`,
  );
}

export function requireSlug(value, label) {
  requireCondition(
    typeof value === "string" && SLUG.test(value),
    `${label} must be lowercase kebab-case`,
  );
}

function unique(items, label) {
  requireCondition(new Set(items).size === items.length, `${label} must be unique`);
}

export function validateSubscriptionBilling(billing) {
  requireCondition(billing?.mode === "subscription", "invalid billing mode");
  requireCondition(billing.paidFallback === false, "paid fallback must be disabled");
  requireCondition(billing.automaticResets === false, "automatic resets must be disabled");
  requireCondition(
    billing.quotaScope === undefined || ["study", "active-provider"].includes(billing.quotaScope),
    "invalid quota scope",
  );
  for (const key of ["weeklyBudgetPercentagePoints", "minimumRemainingPercent"]) {
    requireNumber(billing[key], key, { positive: true });
    requireCondition(billing[key] <= 100, `${key} must not exceed 100`);
  }
  requireNumber(billing.quotaMaxAgeSeconds, "quotaMaxAgeSeconds", { positive: true });
}

export function validateStudy(study) {
  requireCondition(study?.schemaVersion === 1, "study schemaVersion must be 1");
  requireSlug(study.id, "study id");
  requireCondition(
    ["fixture", "calibration", "confirmatory"].includes(study.phase),
    "invalid study phase",
  );
  requireNumber(study.seed, "seed", { integer: true });
  requireCondition(study.seed <= 0xffffffff, "seed must fit in an unsigned 32-bit integer");
  requireNumber(study.repeats, "repeats", { positive: true, integer: true });
  requireCondition(study.repeats <= 100, "repeats must not exceed 100");
  requireCondition(
    JSON.stringify(study.arms) === JSON.stringify(WORKFLOW_ARMS),
    "arms must be normal, report, mcp in that order",
  );
  requireNumber(study.limits?.trialSeconds, "trialSeconds", { positive: true });
  if (study.billing !== undefined) validateSubscriptionBilling(study.billing);
  const subscription = study.billing?.mode === "subscription";
  if (!subscription || study.limits?.trialTokens !== null)
    requireNumber(study.limits?.trialTokens, "trialTokens", { positive: true, integer: true });
  if (subscription) {
    requireCondition(
      study.limits?.trialCostUsd === 0 && study.limits?.studyCostUsd === 0,
      "subscription extra-spend limits must be zero",
    );
  } else {
    requireNumber(study.limits?.trialCostUsd, "trialCostUsd", { positive: true });
    requireNumber(study.limits?.studyCostUsd, "studyCostUsd", { positive: true });
  }
  requireNumber(study.limits?.submissions, "submissions", { positive: true, integer: true });
  requireText(study.protocol, "protocol version");
  requireHash(study.protocolSha256, "protocol digest");
  requireText(study.sitecmd?.version, "SiteCMD version");
  requireCondition(
    COMMIT.test(study.sitecmd?.commit ?? ""),
    "SiteCMD commit must be a full commit SHA",
  );
  requireCondition(typeof study.sitecmd?.dirty === "boolean", "SiteCMD dirty status is required");
  requireHash(study.sitecmd?.mcpSha256, "MCP server digest");
  requireCondition(
    Array.isArray(study.configurations) && study.configurations.length > 0,
    "configurations are required",
  );
  unique(
    study.configurations.map((item) => item.id),
    "configuration ids",
  );
  for (const configuration of study.configurations) {
    requireSlug(configuration.id, "configuration id");
    for (const key of ["agent", "agentVersion", "model", "reasoning", "environment"]) {
      requireText(configuration[key], `configuration ${key}`);
    }
  }
  requireCondition(Array.isArray(study.tasks) && study.tasks.length > 0, "tasks are required");
  unique(
    study.tasks.map((item) => item.id),
    "task ids",
  );
  for (const task of study.tasks) validateTask(task);
  if (study.phase === "confirmatory") {
    requireCondition(!study.sitecmd.dirty, "confirmatory studies require a clean SiteCMD commit");
    requireText(study.registration, "preregistration reference");
    requireText(study.sampleSizeRationale, "sample-size rationale");
    requireCondition(
      study.tasks.every((task) => task.holdout),
      "confirmatory tasks must be held out from tuning",
    );
  }
  const count =
    study.tasks.length * study.configurations.length * study.repeats * study.arms.length;
  requireCondition(count <= 100000, "study exceeds 100,000 trials");
  return study;
}

function validateTask(task) {
  requireSlug(task.id, "task id");
  requireSlug(task.repository, "task repository id");
  requireCondition(["repair", "negative_control"].includes(task.kind), "invalid task kind");
  requireCondition(["code", "web"].includes(task.surface), "invalid task surface");
  requireText(task.category, "task category");
  requireText(task.prompt, "actionable task prompt");
  requireText(task.requirements, "task acceptance requirements");
  requireText(task.provenance, "task provenance");
  requireCondition(typeof task.holdout === "boolean", "task holdout status is required");
  for (const key of ["sourceSha256", "referenceSha256", "graderSha256", "reportSha256"]) {
    requireHash(task[key], `task ${key}`);
  }
  for (const key of ["runtimeSha256", "browserRuntimeSha256"])
    if (task[key] !== undefined) requireHash(task[key], `task ${key}`);
  if (task.sourceFormat !== undefined || task.editableFiles !== undefined) {
    requireCondition(
      task.sourceFormat === "git-tree-v1" && task.surface === "code",
      "invalid task source format",
    );
    requireCondition(
      Array.isArray(task.editableFiles) &&
        task.editableFiles.length <= 1000 &&
        new Set(task.editableFiles).size === task.editableFiles.length &&
        task.editableFiles.every((name) => typeof name === "string" && name.trim().length > 0),
      "repository tasks require unique registered edit paths",
    );
  }
  requireCondition(task.baseline?.regressionsPass === true, "baseline regression checks must pass");
  requireCondition(
    task.baseline?.acceptancePass === (task.kind === "negative_control"),
    "baseline must reproduce the defect, or pass for a negative control",
  );
  requireCondition(
    task.reference?.acceptancePass === true && task.reference?.regressionsPass === true,
    "reference solution must pass acceptance and regression checks",
  );
  requireText(task.validatedBy, "task validation reviewer");
}

export function validateTrial(record, assignment, study) {
  requireCondition(record?.schemaVersion === 1, "trial schemaVersion must be 1");
  requireCondition(record.trialId === assignment.id, "trial id does not match its assignment");
  requireCondition(TRIAL_STATUSES.includes(record.status), "invalid trial status");
  requireCondition(
    record.fixture === (study.phase === "fixture"),
    "fixture status must match the frozen study",
  );
  requireNumber(record.elapsedMs, "elapsedMs");
  if (record.humanActiveMs !== null) requireNumber(record.humanActiveMs, "humanActiveMs");
  requireCondition(
    record.humanActiveMs === null || record.humanActiveMs <= record.elapsedMs,
    "human active time exceeds elapsed time",
  );
  requireCondition(["cold", "warm"].includes(record.setup), "setup must be cold or warm");
  requireText(record.agentVersion, "observed agent version");
  const beforeAgent = record.agentInvoked === false;
  if (beforeAgent) {
    requireCondition(
      ["product_error", "infrastructure_error"].includes(record.status),
      "only setup failures can precede the agent",
    );
    requireCondition(record.model === null, "an uninvoked agent has no observed model");
    requireCondition(
      record.submissions?.length === 0,
      "an uninvoked agent cannot submit a candidate",
    );
  } else if (record.modelSelection === undefined) requireText(record.model, "observed model");
  const config = study.configurations.find((item) => item.id === assignment.configuration);
  if (record.modelSelection !== undefined) {
    const selection = record.modelSelection;
    requireCondition(
      selection.source === "explicit-cli-request" && selection.requested === config.model,
      "requested model differs from the frozen configuration",
    );
    requireCondition(
      Array.isArray(selection.observed),
      "provider-observed models must be an array",
    );
    selection.observed.forEach((model) => requireText(model, "provider-observed model"));
    unique(selection.observed, "provider-observed models");
    if (selection.receipt !== undefined || selection.verified !== undefined) {
      requireText(selection.receipt, "model identity receipt");
      requireCondition(
        typeof selection.verified === "boolean",
        "model identity verification is required",
      );
    }
    if (selection.assurance !== undefined)
      requireCondition(
        selection.assurance === "provider-response-metadata" ||
          (selection.assurance === "explicit-cli-selection" && config.agent === "codex"),
        "invalid model selection assurance",
      );
    requireCondition(
      record.model === (selection.observed.length === 1 ? selection.observed[0] : null),
      "model must equal the single provider-observed identity or remain unknown",
    );
    if (selection.verified && selection.observed.length === 0)
      requireCondition(
        selection.assurance === "explicit-cli-selection" && config.agent === "codex",
        "unobserved model verification requires strict Codex CLI selection evidence",
      );
    requireCondition(
      !selection.observed.some((model) => model !== config.model) || record.status !== "completed",
      "a provider model mismatch must remain a failed trial",
    );
  }
  requireCondition(
    record.agentVersion === config.agentVersion &&
      (beforeAgent || record.modelSelection !== undefined || record.model === config.model),
    "observed model or agent version differs from the frozen configuration",
  );
  requireCondition(Array.isArray(record.submissions), "submissions must be an array");
  requireCondition(
    record.submissions.length <= study.limits.submissions,
    "submission limit exceeded",
  );
  const task = study.tasks.find((item) => item.id === assignment.task);
  let previousMs = -1;
  for (const submission of record.submissions) {
    requireHash(submission.patchSha256, "submitted patch digest");
    requireText(submission.patch, "submitted patch artifact");
    requireNumber(submission.elapsedMs, "submission elapsedMs");
    requireCondition(
      submission.elapsedMs >= previousMs && submission.elapsedMs <= record.elapsedMs,
      "submission timestamps must be ordered within the trial",
    );
    previousMs = submission.elapsedMs;
    requireCondition(
      submission.graderSha256 === task.graderSha256,
      "submission used a different grader",
    );
    for (const key of ["acceptancePass", "regressionsPass", "integrityPass"]) {
      requireCondition(typeof submission[key] === "boolean", `submission ${key} is required`);
    }
    requireText(submission.receipt, "independent grading receipt artifact");
  }
  requireText(record.transcript, "transcript artifact");
  if (assignment.arm === "mcp") {
    requireCondition(
      record.mcp?.serverSha256 === study.sitecmd.mcpSha256,
      "MCP run must identify the frozen SiteCMD server",
    );
    requireText(record.mcp?.trace, "MCP trace artifact");
  } else {
    requireCondition(
      record.mcp === undefined,
      "only the mcp workflow may contain a SiteCMD MCP connection",
    );
  }
  if (record.status !== "completed") requireText(record.failure, "failure explanation");
  return record;
}
