import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Prevent Git commands in checks and fixtures from inheriting the hook's repository. */
export function isolatedGitEnvironment(repositoryRoot, environment) {
  const localVariables = execFileSync("git", ["rev-parse", "--local-env-vars"], {
    cwd: repositoryRoot,
    env: environment,
    encoding: "utf8",
  });
  const isolated = { ...environment };
  for (const name of localVariables.trim().split(/\s+/)) delete isolated[name];
  return isolated;
}

/** Resolve the repository root without leaving URL-encoded path segments intact. */
export function resolveRepositoryRoot(moduleUrl) {
  return path.resolve(path.dirname(fileURLToPath(moduleUrl)), "../..");
}
