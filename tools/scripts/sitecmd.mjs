#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

/** Resolve checkout commands while preserving the shipped CLI's arguments. */
export function invocationFor(input) {
  const args = [...input];
  if (args[0] === "--") args.shift();

  const manifest = path.join(
    repoRoot,
    "apps",
    "desktop",
    "src-tauri",
    "crates",
    "cli",
    "Cargo.toml",
  );
  const toolchain = readFileSync(
    path.join(repoRoot, "apps", "desktop", "src-tauri", "rust-toolchain.toml"),
    "utf8",
  ).match(/^channel\s*=\s*"([^"]+)"/m)?.[1];
  if (!toolchain) throw new Error("The repository Rust toolchain pin is missing.");
  return {
    command: "cargo",
    env: { RUSTUP_TOOLCHAIN: toolchain },
    args: ["run", "--locked", "--quiet", "--manifest-path", manifest, "--", ...args],
  };
}

/** Run one command and propagate errors, exit status, and cancellation. */
export async function run(input, launch = spawn) {
  const invocation = invocationFor(input);
  const child = launch(invocation.command, invocation.args, {
    stdio: "inherit",
    ...(invocation.env ? { env: { ...process.env, ...invocation.env } } : {}),
  });
  const interrupt = () => child.kill("SIGINT");
  const terminate = () => child.kill("SIGTERM");
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", terminate);
  try {
    return await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", (code, signal) => resolve(code ?? (signal === "SIGINT" ? 130 : 143)));
    });
  } finally {
    process.off("SIGINT", interrupt);
    process.off("SIGTERM", terminate);
  }
}

/** Whether node was asked to run this file, directly or through a symlink such
 *  as a linked `sitecmd` bin, which path.resolve alone does not follow. */
export function isEntryPoint(argv1, filename = __filename) {
  if (!argv1) return false;
  try {
    return realpathSync(argv1) === realpathSync(filename);
  } catch {
    return false;
  }
}

if (isEntryPoint(process.argv[1])) {
  try {
    process.exitCode = await run(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
