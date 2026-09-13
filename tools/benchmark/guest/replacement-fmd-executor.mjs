import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const directory = path.dirname(fileURLToPath(import.meta.url));

export function executeFmdCandidate(item, candidate, input) {
  if (process.platform !== "linux" || process.getuid() !== 0) {
    throw new Error("FMD candidate execution requires the isolated guest controller");
  }
  if (input?.operation !== "fmd-device-text" || typeof candidate !== "string") {
    return { error: "InvalidFmdRequest", message: "FMD grading request is invalid" };
  }
  const result = spawnSync(
    process.execPath,
    [path.join(directory, "replacement-fmd-controller.mjs")],
    {
      input: JSON.stringify({ candidate, browserRuntime: item.browserRuntime }),
      encoding: "utf8",
      timeout: 240_000,
      maxBuffer: 8 * 1024 * 1024,
      env: { PATH: "/usr/sbin:/usr/bin:/bin", TZ: "UTC" },
    },
  );
  if (result.status !== 0) {
    const reason = result.error?.code ?? result.status ?? "unknown failure";
    return {
      error: "FmdControllerError",
      message: `${reason}: ${(result.stderr ?? "").slice(-16_000)}`,
    };
  }
  try {
    return JSON.parse(result.stdout);
  } catch {
    return { error: "InvalidFmdOutput", message: (result.stdout ?? "").slice(-2_000) };
  }
}
