#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { desktopInvocation } from "./lib/sitecmd-desktop-command.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..");

/** Resolve checkout commands while preserving the shipped CLI's arguments. */
export function invocationFor(input, platform = process.platform) {
  const args = [...input];
  if (args[0] === "--") args.shift();
  if (args[0] === "open") return desktopInvocation(args.slice(1), platform);

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

if (process.argv[1] && path.resolve(process.argv[1]) === __filename) {
  try {
    process.exitCode = await run(process.argv.slice(2));
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
