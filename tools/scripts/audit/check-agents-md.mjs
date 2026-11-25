#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");

function read(p) {
  return fs.readFileSync(p, "utf8");
}
function exists(p) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function findAgentsMd(dir, out = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === "node_modules" || e.name === "target" || e.name === "dist") continue;
    if (e.name.startsWith(".")) continue;
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) findAgentsMd(abs, out);
    else if (e.isFile() && e.name === "AGENTS.md") out.push(abs);
  }
  return out;
}

const PATH_EXTENSIONS = new Set([
  "rs",
  "ts",
  "tsx",
  "js",
  "mjs",
  "cjs",
  "json",
  "jsonc",
  "toml",
  "yaml",
  "yml",
  "astro",
  "html",
  "css",
  "scss",
  "md",
  "sh",
  "sql",
]);
function extractPaths(content) {
  const re = /`([A-Za-z][A-Za-z0-9_./@-]*?\.(?:[a-z]{2,5}))`/g;
  const set = new Set();
  for (const m of content.matchAll(re)) {
    const candidate = m[1];
    if (!candidate.includes("/")) continue;
    const ext = candidate.split(".").pop().toLowerCase();
    if (!PATH_EXTENSIONS.has(ext)) continue;
    if (candidate.includes("*") || candidate.includes("{")) continue;
    if (candidate.startsWith("//") || candidate.startsWith("http")) continue;
    if (candidate.startsWith("dist/") || candidate.includes("/dist/")) continue;
    set.add(candidate);
  }
  return [...set];
}

function extractPnpmScripts(content) {
  // Only backticked commands are documentation references.
  const re = /`pnpm\s+([a-z][a-z0-9:-]*)\b/g;
  const set = new Set();
  for (const m of content.matchAll(re)) {
    const name = m[1];
    if (name === "install" || name === "exec" || name === "run") continue;
    set.add(name);
  }
  return [...set];
}

function loadAllScripts() {
  const scripts = new Set();
  function addFrom(packageJsonPath) {
    if (!exists(packageJsonPath)) return;
    try {
      const pkg = JSON.parse(read(packageJsonPath));
      for (const name of Object.keys(pkg.scripts || {})) scripts.add(name);
    } catch {
      // Ignore malformed package manifests; other checks report them.
    }
  }
  addFrom(path.join(ROOT, "package.json"));
  const appsDir = path.join(ROOT, "apps");
  if (exists(appsDir)) {
    for (const entry of fs.readdirSync(appsDir, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      addFrom(path.join(appsDir, entry.name, "package.json"));
    }
  }
  return scripts;
}

function resolveRelative(agentsAbs, candidate) {
  // Resolve repository-root paths before guidance-relative paths.
  const repoAbs = path.join(ROOT, candidate);
  if (exists(repoAbs)) return repoAbs;
  const dir = path.dirname(agentsAbs);
  const localAbs = path.join(dir, candidate);
  if (exists(localAbs)) return localAbs;
  const tauriSrcAbs = path.join(ROOT, "apps/desktop/src-tauri/src", candidate);
  if (exists(tauriSrcAbs)) return tauriSrcAbs;
  return null;
}

const allScripts = loadAllScripts();
const agentsFiles = findAgentsMd(ROOT);
const failures = [];

for (const agentsAbs of agentsFiles) {
  const content = read(agentsAbs);
  const rel = path.relative(ROOT, agentsAbs);

  for (const candidate of extractPaths(content)) {
    if (!resolveRelative(agentsAbs, candidate)) {
      failures.push(`${rel}: references missing path \`${candidate}\``);
    }
  }
  for (const script of extractPnpmScripts(content)) {
    if (!allScripts.has(script)) {
      failures.push(`${rel}: references missing pnpm script \`${script}\``);
    }
  }
}

if (failures.length > 0) {
  process.stderr.write("AGENTS.md staleness check failed:\n");
  for (const f of failures) process.stderr.write(`  ${f}\n`);
  process.exit(1);
}
process.stdout.write(`AGENTS.md staleness check passed (${agentsFiles.length} files).\n`);
