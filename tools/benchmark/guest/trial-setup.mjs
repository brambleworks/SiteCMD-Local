import { initializeMcp, openMcp } from "./mcp-session.mjs";

export const trialUrl = "http://localhost:4173";

class UnmappedHandoffError extends Error {
  constructor(projectId) {
    super("This repair has no registered SiteCMD check; no start_fix request was sent");
    this.name = "UnmappedHandoffError";
    this.stage = "handoff";
    this.projectId = projectId;
  }
}

class ProjectSetupError extends Error {
  constructor(stage, projectId, response) {
    super(
      `${stage === "scan" ? "Desktop scan did not complete" : "SiteCMD could not prepare the repair"}: ${JSON.stringify(response)}`,
    );
    this.name = "ProjectSetupError";
    this.stage = stage;
    this.projectId = projectId;
    this.response = response;
  }
}

function responseText(response) {
  return (
    response?.content?.find((item) => item?.type === "text" || "text" in (item ?? {}))?.text ?? ""
  );
}

function confirmatoryTarget(item) {
  const target = item.targetFinding;
  const issue = item.targetIssue;
  if (
    item.confirmatory !== true ||
    typeof target?.checkId !== "string" ||
    typeof target.relativePath !== "string" ||
    !/^sha256:[a-f0-9]{64}$/.test(target.fingerprint ?? "") ||
    issue?.checkId !== target.checkId ||
    issue?.relativePath !== target.relativePath ||
    issue?.fingerprint !== target.fingerprint ||
    typeof issue.title !== "string" ||
    typeof issue.description !== "string" ||
    !["critical", "high", "medium", "low", "info"].includes(issue.severity) ||
    !Number.isSafeInteger(issue.line) ||
    issue.line <= 0
  )
    throw new Error("Confirmatory repair target differs from its registered scanner finding");
  return { target, issue };
}

async function prepareConfirmatoryHandoff(desktop, mcp, item, configuration, projectId) {
  const { target, issue } = confirmatoryTarget(item);
  const agentTool =
    configuration.agent === "claude"
      ? "claude-code"
      : configuration.agent === "codex"
        ? "codex"
        : null;
  if (!agentTool) throw new Error("Unsupported confirmatory agent tool");
  const attempt = await desktop.invoke("create_fix_attempt", {
    args: {
      projectId,
      envUrl: trialUrl,
      checkId: target.checkId,
      agentTool,
      title: issue.title,
      severity: issue.severity,
      description: issue.description,
      whyItMatters: issue.whyNow ?? null,
      evidence: {
        fingerprint: target.fingerprint,
        sourceExcerpt: issue.sourceExcerpt ?? null,
      },
      manualFix: issue.likelyFix ?? null,
      url: trialUrl,
      detectedStack: null,
      codeLocations: [
        {
          label: "Flagged location",
          path: target.relativePath,
          line: issue.line,
          reason: "This is the exact location the scanner flagged.",
        },
      ],
      previousFailure: null,
    },
  });
  if (
    !Number.isSafeInteger(attempt?.id) ||
    attempt.id <= 0 ||
    typeof attempt.kickoffPrompt !== "string" ||
    !attempt.kickoffPrompt.trim()
  )
    throw new ProjectSetupError("handoff", projectId, attempt);
  const brief = await mcp.call("get_fix_brief", { attempt_id: attempt.id });
  const briefText = responseText(brief);
  if (
    brief.isError ||
    !briefText.includes(target.relativePath) ||
    !briefText.includes(`:${issue.line}`)
  )
    throw new ProjectSetupError("handoff", projectId, brief);
  return {
    handoff: attempt.kickoffPrompt,
    attemptId: attempt.id,
    brief: briefText,
  };
}

function scanExecutionDiagnostic(detail) {
  const summary = detail?.summary;
  return {
    summary: summary
      ? {
          id: summary.id,
          status: summary.status,
          webStatus: summary.webStatus,
          webDetail: summary.webDetail,
          codeStatus: summary.codeStatus,
          codeDetail: summary.codeDetail,
        }
      : null,
    runs: Array.isArray(detail?.runs)
      ? detail.runs.map((run) => ({
          id: run.id,
          source: run.source,
          runKind: run.runKind,
          status: run.status,
          statusDetail: run.statusDetail,
          diagnostics: run.diagnostics,
        }))
      : [],
  };
}

export async function prepareProject(
  desktop,
  mounted,
  item,
  product,
  configuration,
  arm,
  log,
  { connect = openMcp } = {},
) {
  const projectId = await desktop.invoke("add_project", {
    name: item.id,
    path: mounted.path,
    framework: null,
    urls: [{ url: trialUrl, environment: "local", source: "benchmark" }],
  });
  const mcp = connect(product.mcp, desktop.database, (event) =>
    log(arm === "mcp" ? "mcp.jsonl" : "setup.jsonl", event),
  );
  try {
    await initializeMcp(mcp, configuration.agent);
    const scan = await mcp.call("run_scan", {
      project_id: projectId,
      url: trialUrl,
      scope: "code",
      wait: true,
    });
    const scanText = responseText(scan);
    if (scan.isError || !/complete: execution #\d+ \(complete\)/.test(scanText)) {
      const executionId = Number(scanText.match(/execution #(\d+)/)?.[1]);
      let execution = null;
      let diagnosticError = null;
      if (Number.isSafeInteger(executionId) && executionId > 0) {
        try {
          execution = scanExecutionDiagnostic(
            await desktop.invoke("get_scan_execution_detail", {
              executionId,
              runId: null,
            }),
          );
        } catch (error) {
          diagnosticError = error.message;
        }
      }
      throw new ProjectSetupError("scan", projectId, {
        scan,
        execution,
        ...(diagnosticError ? { diagnosticError } : {}),
      });
    }
    let handoff = "";
    let attemptId = null;
    let brief = "";
    if (arm === "mcp" && item.kind === "repair") {
      if (item.confirmatory === true) {
        const prepared = await prepareConfirmatoryHandoff(
          desktop,
          mcp,
          item,
          configuration,
          projectId,
        );
        handoff = prepared.handoff;
        attemptId = prepared.attemptId;
        brief = prepared.brief;
      } else {
        if (typeof item.rule !== "string" || !/^[a-z][a-z0-9-]*$/.test(item.rule))
          throw new UnmappedHandoffError(projectId);
        const result = await mcp.call("start_fix", {
          project_id: projectId,
          url: trialUrl,
          check_id: `code_scan.${item.rule}`,
          wait: true,
        });
        if (result.isError || !/Fix attempt #\d+ is briefed/.test(responseText(result)))
          throw new ProjectSetupError("handoff", projectId, result);
        handoff = responseText(result);
      }
    }
    return { projectId, handoff, attemptId, brief };
  } finally {
    mcp.close();
  }
}
