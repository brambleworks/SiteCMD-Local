import os from "node:os";

export function workerCount({
  env = process.env,
  cores = os.availableParallelism(),
  load = os.loadavg()[0],
} = {}) {
  const override = env.VITEST_MAX_WORKERS;
  const requested = Number(override);
  const valid = Number.isSafeInteger(requested) && requested > 0;
  const workers = valid
    ? requested
    : env.CI
      ? 2
      : Math.min(4, Math.max(1, cores - 1 - Math.floor(load)));

  // Vitest parses this variable again after loading the config and lets it
  // override maxWorkers. Rewrite invalid values or ones it would parse differently.
  if (
    env === process.env &&
    override !== undefined &&
    (!valid || Number.parseInt(override) !== workers)
  ) {
    env.VITEST_MAX_WORKERS = String(workers);
  }
  return workers;
}
