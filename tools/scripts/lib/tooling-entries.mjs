import { globSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export async function toolingEntries(root, key) {
  const fragments = globSync("tools/*/tooling.config.mjs", { cwd: root }).sort();
  const configs = await Promise.all(
    fragments.map((file) => import(pathToFileURL(join(root, file)))),
  );
  return configs.flatMap((config) => config[key] ?? []);
}
