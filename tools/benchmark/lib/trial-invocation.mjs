import { pilotPolicy } from "./workflow-pilot.mjs";
import { repositoryStudyPolicy } from "./workflow-repository-study.mjs";
import { confirmatoryStudyPolicies } from "./workflow-confirmatory-study.mjs";

export const agentVersions = { codex: "0.153.0-alpha.5", claude: "2.1.260" };
export const reasoning = "high";
const allowedModels = [
  ...pilotPolicy.models,
  ...repositoryStudyPolicy.models,
  ...confirmatoryStudyPolicies.flatMap((policy) => policy.models),
];

export function trialConfigurations(environment, models = pilotPolicy.models) {
  return models.map(({ agent, model }) => ({
    id: `${agent}-${model.replaceAll(".", "-")}-${reasoning}`,
    agent,
    model,
    agentVersion: agentVersions[agent],
    reasoning,
    environment,
  }));
}

function runtimeEnvironment(repositoryRuntime, channel) {
  if (!repositoryRuntime) return {};
  const expected = `/opt/sitecmd-benchmark/repository-runtimes/${repositoryRuntime.id}/${repositoryRuntime.installationId}`;
  if (
    !/^[a-f0-9]{64}$/.test(repositoryRuntime.id) ||
    !/^[a-f0-9]{24}$/.test(repositoryRuntime.installationId) ||
    repositoryRuntime.directory !== expected
  )
    throw new Error("Invalid benchmark repository runtime");
  const virtualEnvironment = `${expected}/environment/venv`;
  const environment = {
    PATH: `${virtualEnvironment}/bin:/usr/local/bin:/usr/bin:/bin`,
    VIRTUAL_ENV: virtualEnvironment,
    PYTEST_ADDOPTS: "-o cache_dir=/tmp/sitecmd-pytest-cache",
  };
  if (repositoryRuntime.manifest?.caseId === "whoogle-named-config-path")
    Object.assign(environment, {
      STATIC_FOLDER: `${channel}/runtime/static`,
      CONFIG_VOLUME: `${channel}/runtime/config`,
      WHOOGLE_CONFIG_URL: "http://localhost/",
    });
  return environment;
}

export function trialInvocation({
  agent,
  model,
  arm,
  workspace,
  channel,
  proxy,
  repositoryRuntime,
}) {
  if (
    !allowedModels.some((item) => item.agent === agent && item.model === model) ||
    !["normal", "report", "mcp"].includes(arm)
  )
    throw new Error("Unsupported benchmark agent, model or arm");
  const env = {
    PYTHONDONTWRITEBYTECODE: "1",
    PYTHONPYCACHEPREFIX: "/tmp/sitecmd-python-cache",
    ...runtimeEnvironment(repositoryRuntime, channel),
  };
  if (agent === "codex") {
    const shellEnvironment = Object.entries(env)
      .map(([key, value]) => `${key}=${JSON.stringify(value)}`)
      .join(",");
    const config = [
      'forced_login_method="chatgpt"',
      'approval_policy="never"',
      'history.persistence="none"',
      'model_reasoning_effort="high"',
      `shell_environment_policy.set={${shellEnvironment}}`,
      'web_search="disabled"',
      "features.multi_agent=false",
      "features.memories=false",
      "features.hooks=false",
      "features.apps=false",
      'default_permissions="benchmark"',
      `permissions.benchmark={extends=":workspace",filesystem={"/home/runner"="deny","/opt/sitecmd-benchmark/products"="deny",${JSON.stringify(workspace)}="write",${JSON.stringify(channel)}="read",${JSON.stringify(`${channel}/requests`)}="write"${repositoryRuntime ? `,${JSON.stringify(repositoryRuntime.directory)}="read",${JSON.stringify(`${channel}/runtime`)}="write"` : ""}}}`,
      ...(arm === "mcp"
        ? [
            'mcp_servers.sitecmd.command="node"',
            `mcp_servers.sitecmd.args=${JSON.stringify([proxy, channel])}`,
            "mcp_servers.sitecmd.required=true",
            "mcp_servers.sitecmd.tool_timeout_sec=120",
          ]
        : []),
    ];
    return {
      command: "codex",
      args: [
        "exec",
        "--strict-config",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--json",
        "--color",
        "never",
        "--model",
        model,
        "--cd",
        workspace,
        ...config.flatMap((value) => ["-c", value]),
        "-",
      ],
      env,
    };
  }
  const mcpServers = arm === "mcp" ? { sitecmd: { command: "node", args: [proxy, channel] } } : {};
  const settings = {
    sandbox: {
      enabled: true,
      failIfUnavailable: true,
      autoAllowBashIfSandboxed: true,
      allowUnsandboxedCommands: false,
      filesystem: {
        denyRead: ["/home/runner", "/opt/sitecmd-benchmark/products"],
        allowRead: [
          workspace,
          channel,
          ...(repositoryRuntime ? [repositoryRuntime.directory] : []),
        ],
        allowWrite: [`${channel}/requests`, ...(repositoryRuntime ? [`${channel}/runtime`] : [])],
      },
      network: { allowedDomains: [], strictAllowlist: true },
    },
    permissions: {
      deny: [
        "Read(//home/runner/**)",
        "Read(//opt/sitecmd-benchmark/products/**)",
        "Agent",
        "Task",
        "WebFetch",
        "WebSearch",
      ],
    },
  };
  return {
    command: "claude",
    args: [
      "--print",
      "--name",
      "Benchmark",
      "--input-format",
      "stream-json",
      "--verbose",
      "--output-format",
      "stream-json",
      "--no-session-persistence",
      "--disable-slash-commands",
      "--no-chrome",
      "--setting-sources",
      "",
      "--strict-mcp-config",
      "--mcp-config",
      JSON.stringify({ mcpServers }),
      "--settings",
      JSON.stringify(settings),
      "--permission-mode",
      "dontAsk",
      "--tools",
      "Bash,Read,Edit,Write,Glob,Grep",
      "--allowedTools",
      [
        "Bash",
        `Read(/${workspace}/**)`,
        `Edit(/${workspace}/**)`,
        `Write(/${workspace}/**)`,
        ...(arm === "mcp" ? ["mcp__sitecmd__*"] : []),
      ].join(","),
      "--disallowedTools",
      "Agent,Task,WebFetch,WebSearch",
      "--model",
      model,
      "--effort",
      reasoning,
    ],
    env: {
      ...env,
      DISABLE_AUTOUPDATER: "1",
      CLAUDE_CODE_DISABLE_AUTO_MEMORY: "1",
      CLAUDE_CODE_SKIP_PROMPT_HISTORY: "1",
      CLAUDE_CODE_SUBPROCESS_ENV_SCRUB: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
      CLAUDE_CODE_DISABLE_TERMINAL_TITLE: "1",
    },
  };
}
