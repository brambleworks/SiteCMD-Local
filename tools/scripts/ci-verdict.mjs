import { execFileSync } from "node:child_process";

const SHA = /^[a-f0-9]{40}$/;
const RUN_LIMIT = 50;
const QUERY_DELAYS = [0, 20, 20, 20];

function command(file, args) {
  return execFileSync(file, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
  }).trim();
}

function matchingRun(runs, repoPath, tree, trees) {
  for (const run of runs.slice(0, RUN_LIMIT)) {
    if (run.event !== "merge_group" || run.status !== "completed" || run.conclusion !== "success") {
      continue;
    }
    if (!Number.isSafeInteger(run.id) || run.id < 1 || !SHA.test(run.head_sha)) {
      throw new Error("GitHub returned an invalid CI run.");
    }
    if (!trees.has(run.head_sha)) {
      const commit = `${repoPath}/git/commits/${run.head_sha}`;
      const candidateTree = command("gh", ["api", commit, "--jq", ".tree.sha"]);
      if (!SHA.test(candidateTree)) throw new Error("GitHub returned an invalid commit tree.");
      trees.set(run.head_sha, candidateTree);
    }
    if (trees.get(run.head_sha) === tree) return run.id;
  }
  return null;
}

function findVerdict(sha, repository) {
  const tree = command("git", ["rev-parse", "--verify", `${sha}^{tree}`]);
  const repoPath = `/repos/${repository}`;
  const endpoint = `${repoPath}/actions/workflows/ci.yml/runs?event=merge_group&status=success&per_page=${RUN_LIMIT}`;
  const trees = new Map();

  for (const seconds of QUERY_DELAYS) {
    if (seconds > 0) command("sleep", [String(seconds)]);
    const { workflow_runs: runs } = JSON.parse(command("gh", ["api", endpoint]));
    const id = matchingRun(runs, repoPath, tree, trees);
    if (id !== null) return id;
  }
  return "none";
}

try {
  const [flag, sha, ...extra] = process.argv.slice(2);
  const repository = process.env.GITHUB_REPOSITORY ?? "";
  if (
    flag !== "--sha" ||
    !SHA.test(sha) ||
    extra.length ||
    !/^[\w.-]+\/[\w.-]+$/.test(repository)
  ) {
    throw new Error("Set GITHUB_REPOSITORY and pass --sha <commit sha>.");
  }
  console.log(`verdict=${findVerdict(sha, repository)}`);
} catch (error) {
  console.error(`CI verdict lookup failed: ${error.message}`);
  process.exitCode = 1;
}
