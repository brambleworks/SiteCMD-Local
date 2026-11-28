import { commandWords } from "./ci-step-pins.mjs";
import {
  readJobs,
  runCommand,
  workflowFields,
  workflowJobSteps,
} from "./guardrail-workflow-yaml.mjs";
import { tomlText, tomlTokens } from "./toml-fields.mjs";

const CONFIG = "apps/desktop/src-tauri/.config/nextest.toml";

function requestedProfiles(steps) {
  const profiles = new Set();
  for (const step of steps) {
    const run = (runCommand(step) ?? "").replace(/\\\r?\n/g, " ");
    for (const [command, ...args] of commandWords(run)) {
      const [subcommand, nested] = args[0]?.startsWith("+") ? args.slice(1) : args;
      const invokesNextest =
        subcommand === "nextest" || (subcommand === "llvm-cov" && nested === "nextest");
      if (command !== "cargo-nextest" && !(command === "cargo" && invokesNextest)) continue;
      for (let index = 0; index < args.length; index++) {
        const arg = args[index];
        if (arg === "--" || arg.startsWith("#")) break;
        const profile = arg === "--profile" ? args[++index] : arg.match(/^--profile=(.*)$/)?.[1];
        if (profile !== undefined) profiles.add(profile.replace(/^(['"])(.*)\1$/, "$2"));
      }
    }
  }
  return profiles;
}

function configuredProfiles(read) {
  let source;
  try {
    source = read(CONFIG);
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
    return new Set();
  }
  const tokens = [...tomlTokens(source)]
    .map(([token]) => token)
    .filter((token) => !token.startsWith("#"));
  const profiles = new Set();
  for (const [index, token] of tokens.entries()) {
    if (token !== "[" || (index > 0 && tokens[index - 1] !== "\n")) continue;
    const [table, dot, profile, close, next] = tokens.slice(index + 1, index + 6);
    if (tomlText(table) === "profile" && dot === "." && close === "]" && (!next || next === "\n")) {
      profiles.add(tomlText(profile));
    }
  }
  return profiles;
}

export function nextestProfileFailures(read, workflow, steps) {
  const requested = requestedProfiles([...steps.values()].flat());
  if (requested.size === 0) return [];
  const configured = configuredProfiles(read);
  return [...requested]
    .filter((profile) => !configured.has(profile))
    .map(
      (profile) =>
        `${workflow} uses nextest profile ${profile}, but ${CONFIG} has no [profile.${profile}] table.`,
    );
}

export function releaseNextestProfileFailures(read, source) {
  return nextestProfileFailures(
    read,
    "release.yml",
    workflowJobSteps(readJobs(workflowFields(source))),
  );
}
