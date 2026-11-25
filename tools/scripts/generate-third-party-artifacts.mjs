#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const WORKSPACE = "apps/desktop/src-tauri";
const CLI_MANIFEST = "crates/cli/Cargo.toml";
const INVENTORY_PATH = path.join(ROOT, "THIRD_PARTY_DEPENDENCIES.json");
const LICENSES_PATH = path.join(ROOT, "THIRD_PARTY_LICENSES.txt");
const ENGINE_LICENSES = "engine/local-engine.wasm.LICENSES.txt";
const MAX_COMMAND_OUTPUT = 128 * 1024 * 1024;
const LICENSE_FILE_STEMS = ["license", "licence", "copying", "notice"];

function run(command, args) {
  const result = spawnSync(command, args, {
    cwd: path.join(ROOT, WORKSPACE),
    encoding: "utf8",
    maxBuffer: MAX_COMMAND_OUTPUT,
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed:\n${result.stderr || result.stdout}`);
  }
  return result.stdout;
}

function normalizeText(value) {
  return (
    value
      .replace(/\r\n?/g, "\n")
      .replace(/[\t ]+$/gm, "")
      .trimEnd() + "\n"
  );
}

function isLicenseFileName(name) {
  const lower = name.toLowerCase();
  return LICENSE_FILE_STEMS.some((stem) => {
    if (lower === stem) return true;
    if (!lower.startsWith(stem)) return false;
    return [".", "_", "-"].includes(lower.charAt(stem.length));
  });
}

function candidateLicenseFiles(directory, explicitPath) {
  const candidates = new Set();
  if (explicitPath) {
    const resolved = path.resolve(directory, explicitPath);
    if (existsSync(resolved) && statSync(resolved).isFile()) candidates.add(resolved);
  }
  for (const name of readdirSync(directory).sort()) {
    if (!isLicenseFileName(name)) continue;
    const resolved = path.join(directory, name);
    if (statSync(resolved).isFile()) candidates.add(resolved);
  }
  return [...candidates];
}

function collectRustPackages(manifestRelativePath, scope, packageRecords) {
  const manifest = ["--manifest-path", manifestRelativePath];
  const tree = run("cargo", [
    "tree",
    "--locked",
    "--target",
    "all",
    "--edges",
    "normal,build",
    "--prefix",
    "none",
    "--format",
    "{p}",
    "--color",
    "never",
    ...manifest,
  ]);
  const active = new Set(
    [...tree.matchAll(/^(\S+) v(\S+)/gm)].map(([, name, version]) => `${name}@${version}`),
  );
  const { packages } = JSON.parse(
    run("cargo", ["metadata", "--locked", "--format-version", "1", ...manifest]),
  );

  for (const pkg of packages) {
    const nameVersion = `${pkg.name}@${pkg.version}`;
    if (!pkg.source || !active.has(nameVersion)) continue;
    const key = `cargo:${nameVersion}:${pkg.source}`;
    let record = packageRecords.get(key);
    if (!record) {
      record = {
        ecosystem: "cargo",
        name: pkg.name,
        version: pkg.version,
        license: pkg.license ?? null,
        repository: pkg.repository ?? null,
        source: pkg.source,
        scopes: new Set(),
        licensePaths: candidateLicenseFiles(path.dirname(pkg.manifest_path), pkg.license_file),
      };
      packageRecords.set(key, record);
    }
    record.scopes.add(scope);
  }
}

function embeddedEngineLicenses() {
  const sidecar = path.join(ROOT, ENGINE_LICENSES);
  if (!existsSync(sidecar)) {
    if (existsSync(path.join(ROOT, "engine.lock"))) {
      throw new Error(
        `engine.lock requires ${ENGINE_LICENSES}. Restore the signed license sidecar for the pinned engine.`,
      );
    }
    return [];
  }
  const text = readFileSync(sidecar, "utf8");
  if (!text.trim()) throw new Error(`${ENGINE_LICENSES} is empty.`);
  return ["", "Embedded engine module licenses", "", text.trimEnd()];
}

function buildArtifacts() {
  const engineSections = embeddedEngineLicenses();
  const packageRecords = new Map();
  collectRustPackages(CLI_MANIFEST, "cli-rust", packageRecords);

  const licenseTexts = new Map();
  const packages = [...packageRecords.values()]
    .sort((a, b) =>
      [a.ecosystem, a.name, a.version]
        .join(":")
        .localeCompare([b.ecosystem, b.name, b.version].join(":")),
    )
    .map((record) => {
      const packageId = `${record.ecosystem}:${record.name}@${record.version}`;
      const licenseFiles = record.licensePaths.map((licensePath) => {
        const content = normalizeText(readFileSync(licensePath, "utf8"));
        const sha256 = createHash("sha256").update(content).digest("hex");
        const entry = licenseTexts.get(sha256) ?? {
          content,
          filenames: new Set(),
          packages: new Set(),
        };
        entry.filenames.add(path.basename(licensePath));
        entry.packages.add(packageId);
        licenseTexts.set(sha256, entry);
        return { name: path.basename(licensePath), sha256 };
      });
      return {
        ecosystem: record.ecosystem,
        name: record.name,
        version: record.version,
        license: record.license,
        repository: record.repository,
        source: record.source,
        scopes: [...record.scopes].sort(),
        licenseFiles,
      };
    });

  const inventory = `${JSON.stringify(
    {
      schemaVersion: 1,
      generatedFrom: [
        `${WORKSPACE}/Cargo.lock`,
        `${WORKSPACE}/Cargo.toml`,
        `${WORKSPACE}/${CLI_MANIFEST}`,
      ],
      packages,
    },
    null,
    2,
  )}\n`;

  const sections = [...licenseTexts.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([sha256, entry]) =>
      [
        "================================================================================",
        `SHA-256: ${sha256}`,
        `Packages: ${[...entry.packages].sort().join(", ")}`,
        `Upstream files: ${[...entry.filenames].sort().join(", ")}`,
        "================================================================================",
        entry.content.trimEnd(),
      ].join("\n"),
    );
  const licenses = [
    "SiteCMD third-party license texts",
    "",
    "Package identities and SPDX expressions are recorded in THIRD_PARTY_DEPENDENCIES.json.",
    "Identical upstream license files are deduplicated by SHA-256 below.",
    "A package without an upstream license file remains identified by its declared expression.",
    "",
    ...sections,
    ...engineSections,
    "",
  ].join("\n");
  return { inventory, licenses };
}

function checkFile(file, expected) {
  return existsSync(file) && readFileSync(file, "utf8") === expected;
}

const artifacts = buildArtifacts();
if (process.argv.includes("--check")) {
  const stale = [
    [INVENTORY_PATH, artifacts.inventory],
    [LICENSES_PATH, artifacts.licenses],
  ]
    .filter(([file, expected]) => !checkFile(file, expected))
    .map(([file]) => path.relative(ROOT, file));
  if (stale.length > 0) {
    throw new Error(
      `Third-party artifacts are stale: ${stale.join(", ")}. Run pnpm legal:generate.`,
    );
  }
  console.log(`Third-party artifacts are current (${artifacts.inventory.length} inventory bytes).`);
} else {
  writeFileSync(INVENTORY_PATH, artifacts.inventory);
  writeFileSync(LICENSES_PATH, artifacts.licenses);
  console.log("Generated THIRD_PARTY_DEPENDENCIES.json and THIRD_PARTY_LICENSES.txt.");
}
