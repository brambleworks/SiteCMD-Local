#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const TOML = path.join(ROOT, "apps/desktop/src-tauri/rust-toolchain.toml");
const DENY_TOML = path.join(ROOT, "apps/desktop/src-tauri/deny.toml");
const RELEASE_YML = path.join(ROOT, ".github/workflows/release.yml");

const failures = [];

function read(p) {
  return fs.readFileSync(p, "utf8");
}

if (!fs.existsSync(TOML)) {
  process.stderr.write(
    `Rust toolchain pin missing: expected ${path.relative(ROOT, TOML)}.\n` +
      "This file is what keeps local clippy and release clippy on the same version.\n",
  );
  process.exit(1);
}

const toml = read(TOML);

// Require an explicit toolchain version.
const channelMatch = toml.match(/^\s*channel\s*=\s*"([^"]+)"/m);
const channel = channelMatch?.[1];
if (!channel) {
  failures.push('rust-toolchain.toml has no `channel = "..."` line.');
} else if (!/^\d+\.\d+\.\d+$/.test(channel)) {
  failures.push(
    `rust-toolchain.toml channel is "${channel}" - it must pin an explicit X.Y.Z version. ` +
      "Floating channels (stable/beta/nightly) reintroduce the CI drift this guards against.",
  );
}

// Confirm rustup honors the repository pin locally.
if (channel && /^\d+\.\d+\.\d+$/.test(channel)) {
  try {
    const out = execFileSync("rustc", ["--version"], {
      cwd: path.dirname(TOML),
      encoding: "utf8",
    });
    const active = out.match(/rustc (\d+\.\d+\.\d+)/)?.[1];
    if (active !== channel) {
      failures.push(
        `Active rustc is ${active ?? "unknown"} but rust-toolchain.toml pins ${channel}. ` +
          `Run \`rustup toolchain install ${channel}\` so local verification matches the release.`,
      );
    }
  } catch {
    failures.push(
      "Could not run `rustc --version` - install rustup so verify:push can gate on the pinned toolchain.",
    );
  }
}

// Require tools used by local and release gates.
const componentsBlock = toml.match(/components\s*=\s*\[([^\]]*)\]/)?.[1] ?? "";
for (const required of ["clippy", "rustfmt"]) {
  if (!componentsBlock.includes(`"${required}"`)) {
    failures.push(`rust-toolchain.toml components must include "${required}".`);
  }
}

// Keep release-matrix targets installed by the pinned toolchain.
const tomlTargetsBlock = toml.match(/targets\s*=\s*\[([^\]]*)\]/)?.[1] ?? "";
const tomlTargets = new Set([...tomlTargetsBlock.matchAll(/"([^"]+)"/g)].map((m) => m[1]));
if (fs.existsSync(RELEASE_YML)) {
  const releaseTargets = new Set();
  for (const m of read(RELEASE_YML).matchAll(/rust_toolchain_targets:\s*([^\n#]+)/g)) {
    for (const triple of m[1].split(",")) {
      const trimmed = triple.trim();
      if (trimmed) releaseTargets.add(trimmed);
    }
  }
  for (const triple of releaseTargets) {
    if (!tomlTargets.has(triple)) {
      failures.push(
        `release.yml cross-compiles "${triple}" but rust-toolchain.toml does not list it in \`targets\`. ` +
          "The pinned toolchain needs every matrix target or the release build fails.",
      );
    }
  }
  const denyTargets = new Set(
    [...read(DENY_TOML).matchAll(/triple\s*=\s*"([^"]+)"/g)].map((match) => match[1]),
  );
  for (const triple of releaseTargets) {
    if (!denyTargets.has(triple)) {
      failures.push(
        `release.yml ships "${triple}" but deny.toml does not inspect its dependency graph.`,
      );
    }
  }
}

if (failures.length > 0) {
  process.stderr.write("Rust toolchain pin check failed:\n");
  for (const f of failures) process.stderr.write(`  - ${f}\n`);
  process.exit(1);
}
process.stdout.write(`Rust toolchain pin check passed (channel ${channel}).\n`);
