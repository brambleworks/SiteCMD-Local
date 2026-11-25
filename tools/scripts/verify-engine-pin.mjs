import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";

try {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node tools/scripts/verify-engine-pin.mjs <binary>");
  }
  const binary = path.resolve(process.argv[2]);
  const { sha256: expected } = JSON.parse(readFileSync("engine.lock", "utf8"));
  if (typeof expected !== "string" || !/^[0-9a-f]{64}$/.test(expected)) {
    throw new Error("engine.lock has no valid SHA-256 digest.");
  }
  const version = execFileSync(binary, ["--version"], { encoding: "utf8" }).trim();
  if (version.includes("+unpinned"))
    throw new Error(`CLI --version contains +unpinned: ${version}.`);

  const info = JSON.parse(execFileSync(binary, ["engine", "info", "--json"], { encoding: "utf8" }));
  if (info.sha256 !== expected) {
    throw new Error(
      `Embedded engine SHA-256 ${info.sha256} does not match engine.lock (${expected}).`,
    );
  }
  console.log(`Verified embedded engine SHA-256 ${expected} (load time: ${info.load_ms} ms).`);
} catch (error) {
  console.error(`Engine pin verification failed: ${error.message}`);
  process.exitCode = 1;
}
