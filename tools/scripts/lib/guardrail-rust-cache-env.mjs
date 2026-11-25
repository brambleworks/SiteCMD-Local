import { children, runCommand, scalar } from "./guardrail-workflow-yaml.mjs";

const defaultPrefixes = ["CARGO", "CC", "CFLAGS", "CXX", "CMAKE", "RUST"];

export function isRustCache(step) {
  return /^Swatinem\/rust-cache@/i.test(scalar(step.get("uses")) ?? "");
}

export function sharedRustCaches(file, workflow, jobs, steps) {
  const caches = [];
  for (const [job, jobSteps] of steps) {
    for (const [index, step] of jobSteps.entries()) {
      if (!isRustCache(step)) continue;
      const inputs = children(step.get("with"));
      const key = scalar(inputs.get("shared-key"));
      if (!key) continue;
      const prefixes = [
        ...defaultPrefixes,
        ...((scalar(inputs.get("env-vars")) ?? "").match(/\S+/g) ?? []),
      ];
      const hashedName = (name) => prefixes.some((prefix) => name.startsWith(prefix));
      const env = new Map(
        [workflow, jobs.get(job), step].flatMap((level) => [...children(level.get("env"))]),
      );
      const hashed = new Map(
        [...env].flatMap(([name, field]) => {
          const value = scalar(field);
          return value && hashedName(name) ? [[name, value]] : [];
        }),
      );
      const writesBeforeRestore = new Set(
        jobSteps.slice(0, index).flatMap((prior) => {
          const run = runCommand(prior) ?? "";
          if (!run.includes("GITHUB_ENV")) return [];
          return [...run.matchAll(/\b([A-Z_][A-Z0-9_]*)\s*(?:=|<<)/g)]
            .map(([, name]) => name)
            .filter(hashedName);
        }),
      );
      caches.push({
        file,
        job,
        key,
        prefix: scalar(inputs.get("prefix-key")) || "v0-rust",
        hashed,
        writesBeforeRestore,
      });
    }
  }
  return caches;
}

export function sharedRustCacheFailures(caches) {
  const failures = [];
  for (const [index, cache] of caches.entries()) {
    if (cache.writesBeforeRestore.size) {
      failures.push(
        `${cache.file} job ${cache.job} rust-cache environment for shared-key ${cache.key} must declare ${[...cache.writesBeforeRestore].sort().join(", ")} in env before restore instead of writing it to GITHUB_ENV.`,
      );
    }
    const other = caches.slice(0, index).find((candidate) => {
      if (cache.key !== candidate.key) return false;
      return (
        cache.prefix === candidate.prefix ||
        [cache, candidate].some(({ prefix }) => prefix.includes("${{"))
      );
    });
    if (!other) continue;
    const drift = [...new Set([...cache.hashed.keys(), ...other.hashed.keys()])]
      .filter((name) => cache.hashed.get(name) !== other.hashed.get(name))
      .sort();
    if (drift.length) {
      failures.push(
        `${cache.file} job ${cache.job} rust-cache environment for shared-key ${cache.key} differs from ${other.file} job ${other.job} (${drift.join(", ")}).`,
      );
    }
  }
  return failures;
}
