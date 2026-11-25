import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { parseNormalWasmtimeFeatures } from "./lib/guardrail-engine-host-rules.mjs";

const policy = readFileSync(
  new URL("../../apps/desktop/src-tauri/deny.toml", import.meta.url),
  "utf8",
);

describe("Rust dependency policy", () => {
  it("extracts only the Wasmtime features from Cargo's normal dependency tree", () => {
    // Bug: Dropping a Cranelift feature from Cargo's output lets a compiler ship in the CLI.
    const normal =
      "wasmtime v48.0.10\tonce_cell,runtime,std,wasmtime-jit-icache-coherence\t\n" +
      "sitecmd-cli v2.0.0 (/checkout/apps/desktop/src-tauri/crates/cli)\tdefault\t\n";
    const withCompiler =
      "wasmtime v48.0.10\tcranelift,once_cell,runtime,std,wasmtime-jit-icache-coherence\t\n" +
      "sitecmd-cli v2.0.0 (/checkout/apps/desktop/src-tauri/crates/cli)\tdefault\t\n";
    const features = ["once_cell", "runtime", "std", "wasmtime-jit-icache-coherence"];
    expect(parseNormalWasmtimeFeatures(normal)).toEqual(features);
    expect(parseNormalWasmtimeFeatures(withCompiler)).toEqual(["cranelift", ...features]);
  });

  it("bans every version of the unmaintained chrono crate", () => {
    // RUSTSEC-2026-0543: every chrono version is unmaintained.
    const bans = policy.split(/^\[bans\]\s*$/m)[1]?.split(/^\[/m)[0];
    const denied = bans?.match(/^deny\s*=\s*\[([^\]]*)\]/m)?.[1];
    expect(denied).toMatch(
      /\{\s*name\s*=\s*"chrono",\s*reason\s*=\s*"[^"]*RUSTSEC-2026-0543[^"]*"\s*\}/,
    );
  });
});
