import { spawnSync } from "node:child_process";
import { pilotPolicy } from "./workflow-pilot.mjs";
import { repositoryStudyPolicy } from "./workflow-repository-study.mjs";
import { confirmatoryStudyPolicies } from "./workflow-confirmatory-study.mjs";

const models = [
  ...pilotPolicy.models,
  ...repositoryStudyPolicy.models,
  ...confirmatoryStudyPolicies.flatMap((policy) => policy.models),
].filter(
  (item, index, entries) =>
    entries.findIndex(
      (candidate) => candidate.agent === item.agent && candidate.model === item.model,
    ) === index,
);

const BILLING_ENVIRONMENT =
  /^(ANTHROPIC_|OPENAI_|AZURE_OPENAI_|CODEX_API_|CLAUDE_CODE_USE_|CLAUDE_CODE_OAUTH_)/;

function parseClaudeStatus(result) {
  if (result.status !== 0) return false;
  try {
    const status = JSON.parse(result.stdout);
    return (
      status.loggedIn === true &&
      status.authMethod === "claude.ai" &&
      status.apiProvider === "firstParty"
    );
  } catch {
    return false;
  }
}

/** Inspect local CLI authentication without issuing prompts or exposing account details. */
export function probeAgentAccounts({ environment = process.env, run = spawnSync } = {}) {
  const blockedEnvironmentVariables = Object.keys(environment)
    .filter((key) => BILLING_ENVIRONMENT.test(key))
    .sort();
  const invoke = (command, args) => {
    try {
      return run(command, args, {
        env: environment,
        shell: false,
        encoding: "utf8",
        timeout: 5000,
        maxBuffer: 65536,
        stdio: ["ignore", "pipe", "pipe"],
      });
    } catch {
      return { status: null };
    }
  };
  const accounts = [...new Set(models.map(({ agent }) => agent))].map((agent) => {
    const versionResult = invoke(agent, ["--version"]);
    const status = invoke(
      agent,
      agent === "codex" ? ["login", "status"] : ["auth", "status", "--json"],
    );
    const versionPattern =
      agent === "codex"
        ? /^codex-cli ([\d]+\.[\d]+\.[\d]+(?:-[\w.]+)?)$/m
        : /^([\d]+\.[\d]+\.[\d]+) \(Claude Code\)$/m;
    const version =
      versionResult.status === 0
        ? (versionPattern.exec(versionResult.stdout ?? "")?.[1] ?? null)
        : null;
    const subscription =
      agent === "codex"
        ? status.status === 0 &&
          /^Logged in using ChatGPT\s*$/m.test(`${status.stdout ?? ""}\n${status.stderr ?? ""}`)
        : parseClaudeStatus(status);
    return {
      agent,
      models: models.filter((item) => item.agent === agent).map(({ model }) => model),
      version,
      subscriptionAuthenticated: subscription,
      modelAvailabilityVerified: false,
    };
  });
  const blockers = blockedEnvironmentVariables.map(
    (key) => `${key}: remove the billing/auth routing override from the benchmark process`,
  );
  for (const account of accounts) {
    if (!account.version) blockers.push(`${account.agent}: CLI version could not be read`);
    if (!account.subscriptionAuthenticated)
      blockers.push(`${account.agent}: subscription authentication could not be verified`);
  }
  const subscriptionAccountsVerified = blockers.length === 0;
  blockers.push(
    "This account probe does not verify the guest execution harness or its isolation checks",
    "A frozen, independently validated case corpus is required and is not checked by this command",
    "Fresh quota evidence and disabled extra paid usage must be verified before execution",
    "Exact model availability and runtime configuration have not been tested",
  );
  return {
    subscriptionAccountsVerified,
    readyToRun: false,
    accounts,
    blockedEnvironmentVariables,
    blockers,
  };
}
