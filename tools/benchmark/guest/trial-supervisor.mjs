import { spawn } from "node:child_process";
import { appendFileSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { evaluateQuota } from "../lib/workflow-quota.mjs";
import { systemCommand } from "./desktop-session.mjs";
import { watchProviderEvents } from "./trial-events.mjs";
import { trialInput } from "./trial-input.mjs";

export function launchAgent({
  id,
  invocation,
  workspace,
  prompt,
  directory,
  plan,
  baseline,
  currentQuota,
  requestedModel,
  provider,
  log,
  initialized = () => {},
}) {
  const unit = `sitecmd-agent-${id}`;
  const startedAt = Date.now();
  let failure = null;
  let status = "completed";
  let size = 0;
  let exited = false;
  let evidenceComplete = true;
  const quota = () => {
    if (existsSync(`/run/sitecmd-benchmark-cancel-${id}`))
      throw new Error("Trial cancelled by the operator");
    const current = JSON.parse(readFileSync(currentQuota, "utf8"));
    const outcome = evaluateQuota(baseline, current, plan.study.billing, Date.now(), provider);
    log("quota-events.jsonl", { checkedAt: new Date().toISOString(), current, outcome });
    if (!outcome.quotaAllowed) throw new Error(outcome.blockers.join("; "));
    return current;
  };
  quota();
  for (const name of ["transcript.jsonl", "stderr.log"])
    writeFileSync(path.join(directory, name), "", { flag: "wx", mode: 0o600 });
  const child = spawn(
    "systemd-run",
    [
      "--quiet",
      "--wait",
      "--pipe",
      "--collect",
      `--unit=${unit}`,
      "--property=User=runner",
      `--working-directory=${workspace}`,
      "--property=MemoryMax=2G",
      "--property=TasksMax=128",
      "--property=CPUQuota=200%",
      "--property=LimitFSIZE=67108864",
      "--property=TemporaryFileSystem=/tmp:size=256M,mode=1777",
      `--property=RuntimeMaxSec=${plan.study.limits.trialSeconds}`,
      ...Object.entries(invocation.env).map(([key, value]) => `--setenv=${key}=${value}`),
      `/usr/local/bin/${invocation.command}`,
      ...invocation.args,
    ],
    { stdio: ["pipe", "pipe", "pipe"] },
  );
  const stop = (reason, nextStatus = "infrastructure_error") => {
    if (failure || exited) return;
    failure = reason;
    status = nextStatus;
    const stopper = spawn("systemctl", ["stop", unit], { stdio: "ignore" });
    stopper.on("error", () => child.kill("SIGTERM"));
    stopper.on("close", (code) => {
      if (code !== 0) child.kill("SIGTERM");
    });
  };
  const observer = watchProviderEvents(requestedModel, stop, invocation.command);
  const input = trialInput({
    agent: invocation.command,
    stdin: child.stdin,
    prompt,
    initialized,
    fail: stop,
  });
  const capture = (name) => (chunk) => {
    size += chunk.length;
    if (size > 64 * 1024 * 1024) {
      if (evidenceComplete)
        log("quota-events.jsonl", {
          evidenceTruncated: true,
          reason: "Transcript exceeded 64 MiB",
        });
      evidenceComplete = false;
      stop("Transcript exceeded 64 MiB");
      return;
    }
    appendFileSync(path.join(directory, name), chunk);
    if (name === "transcript.jsonl") {
      observer.write(chunk);
      if (!failure) input.write(chunk);
    }
  };
  child.stdout.on("data", capture("transcript.jsonl"));
  child.stderr.on("data", capture("stderr.log"));
  child.stdin.on("error", () => {});
  const timer = setInterval(() => {
    if (Date.now() - startedAt >= plan.study.limits.trialSeconds * 1000) {
      stop("Trial deadline reached", "timeout");
      return;
    }
    try {
      quota();
    } catch (error) {
      stop(error.message);
    }
  }, 5000);
  const done = new Promise((resolve) => {
    child.once("error", (error) => {
      failure = error.message;
      status = "agent_error";
    });
    child.once("close", (code) => {
      observer.end();
      exited = true;
      clearInterval(timer);
      if (code !== 0 && !failure) {
        status = "agent_error";
        failure = `Agent exited with status ${code}`;
      }
      if (Date.now() - startedAt >= plan.study.limits.trialSeconds * 1000) {
        status = "timeout";
        failure = failure || "Trial deadline reached";
      }
      if (!readFileSync(path.join(directory, "transcript.jsonl")).length)
        appendFileSync(
          path.join(directory, "transcript.jsonl"),
          `${JSON.stringify({ benchmarkError: failure || "No provider events emitted" })}\n`,
        );
      if (!readFileSync(path.join(directory, "stderr.log")).length)
        appendFileSync(path.join(directory, "stderr.log"), "No stderr output\n");
      resolve({
        status,
        failure,
        elapsedMs: Date.now() - startedAt,
        evidenceComplete,
      });
    });
  });
  return {
    done,
    quota,
    stop,
    elapsed: () => Date.now() - startedAt,
    freeze: () => systemCommand("systemctl", ["freeze", unit]),
    thaw: () => {
      if (!exited && !failure) systemCommand("systemctl", ["thaw", unit]);
    },
  };
}
