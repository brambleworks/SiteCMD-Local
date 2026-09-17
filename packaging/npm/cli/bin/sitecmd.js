#!/usr/bin/env node
// Thin launcher for the sitecmd CLI. The real program is a self-contained,
// code-signed Rust binary shipped in the platform-specific optional
// dependencies below; npm installs only the one matching this machine, and
// this file's whole job is to find it and hand over. No install scripts, no
// download-at-install: the binary bytes come from the package itself.
"use strict";

const { spawnSync } = require("node:child_process");

const PLATFORM_PACKAGES = {
  "darwin arm64": ["@sitecmd/cli-darwin-universal", "sitecmd"],
  "darwin x64": ["@sitecmd/cli-darwin-universal", "sitecmd"],
  "linux x64": ["@sitecmd/cli-linux-x64", "sitecmd"],
  "linux arm64": ["@sitecmd/cli-linux-arm64", "sitecmd"],
  "win32 x64": ["@sitecmd/cli-win32-x64", "sitecmd.exe"],
};

const key = `${process.platform} ${process.arch}`;
const entry = PLATFORM_PACKAGES[key];
if (!entry) {
  console.error(
    `@sitecmd/cli ships no prebuilt binary for ${key}. The standalone ` +
      "installer covers the supported platforms: " +
      "https://sitecmd.com/docs/cli#installation",
  );
  process.exit(1);
}

let binary;
try {
  binary = require.resolve(`${entry[0]}/bin/${entry[1]}`);
} catch {
  console.error(
    `${entry[0]} is missing. It installs as an optional dependency of ` +
      "@sitecmd/cli, so reinstall without omitting optional dependencies " +
      "(no --no-optional / --omit=optional). The standalone installer also " +
      "works: https://sitecmd.com/docs/cli#installation",
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });
if (result.error) {
  console.error(result.error.message);
  process.exit(1);
}
if (result.signal) {
  process.kill(process.pid, result.signal);
}
process.exit(result.status ?? 1);
