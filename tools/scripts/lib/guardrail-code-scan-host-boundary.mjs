import { stripNonCode } from "./guardrail-source-text.mjs";
import { ENGINE_CRATES } from "./publication-history-rules.mjs";

const native = "apps/desktop/src-tauri/src/core";
const sessionHost = `${native}/audit/session_host`;
const autofix = "apps/desktop/src-tauri/src/cli/autofix";
const constantsPath = "apps/desktop/src-tauri/src/constants.rs";
const [engineCrate] = ENGINE_CRATES.map((name) => name.replaceAll("-", "_"));
const privateImports = new RegExp(
  `\\b(?:${ENGINE_CRATES.map((name) => name.replaceAll("-", "_")).join("|")})\\b`,
);

const factModules = [
  "database_snapshot",
  "database_targets",
  "engine_facts",
  "engine_io",
  "git",
  "project_listing",
  "safe_fs",
  "scan_scope",
];

const externalFactImportRoots = [
  "std",
  "sitecmd_protocol",
  "sitecmd_engine_host",
  "cap_std",
  "cap_fs_ext",
  "ignore",
  "libc",
  "postgres",
  "rusqlite",
  "serde_json",
  "tempfile",
  "thiserror",
  "tokio::runtime::Runtime",
  "tracing::instrument",
  "url",
];

const localFactImportRoots = [
  "crate::constants",
  ...factModules.map((module) => `crate::core::${module}`),
];

// constants.rs derives two numbers from the private engine, which no fact or
// host module may name itself.
const fileExternalRoots = new Map([
  [
    constantsPath,
    [
      `${engineCrate}::browser::AxeEvidenceCaps`,
      `${engineCrate}::checks::seo::links::BROKEN_LINK_INTERNAL_CONCURRENCY`,
    ],
  ],
  [
    `${native}/git.rs`,
    [
      "base64::Engine",
      "base64::engine::general_purpose::STANDARD",
      "serde",
      "tokio::task::spawn_blocking",
      "ts_rs::TS",
    ],
  ],
]);

const sessionLocalPaths = new Map([
  [constantsPath, new Set(["super::USER_AGENT"])],
  [
    `${native}/git.rs`,
    new Set([
      "crate::db::EventSeverity",
      "crate::db::EventSource",
      "crate::db::EventType",
      "crate::db::SiteEvent",
      "crate::db::timestamp_text_to_ms",
      "crate::time::now_utc",
    ]),
  ],
  [`${sessionHost}/report.rs`, new Set(["super::SessionReport", "super::native_issue"])],
  [
    `${sessionHost}/tests.rs`,
    new Set(["super::answer_batch", "super::resume_round", "super::ReadBudget"]),
  ],
]);

function factPathAllowed(path, file) {
  const matchesRoot = (candidate, root) => candidate === root || candidate.startsWith(`${root}::`);
  const external = [...externalFactImportRoots, ...(fileExternalRoots.get(file) ?? [])];
  if (path.startsWith("::")) {
    return external.some((root) => matchesRoot(path.slice(2), root));
  }
  return (
    path === "crate::core::filesystem::MAX_FILE_BYTES" ||
    sessionLocalPaths.get(file)?.has(path) ||
    localFactImportRoots.some((root) => matchesRoot(path, root)) ||
    external.some((root) => matchesRoot(path, root))
  );
}

const IDENTIFIER = /^[A-Za-z_]\w*$/;

/** `a::b`, `::a::b` or `a::b::{c, d}`, with an optional `as` alias on a single path. */
function parseUseTree(tree) {
  const segmentsValid = (path) =>
    path
      .replace(/^::/, "")
      .split("::")
      .every((segment) => /^\w+$/.test(segment));
  const brace = tree.indexOf("::{");
  if (brace !== -1) {
    const path = tree.slice(0, brace);
    const members = tree.slice(brace + 3, -1);
    if (!tree.endsWith("}") || /[{}]/.test(members) || !segmentsValid(path)) return null;
    return { path, members };
  }
  const [path, alias, ...rest] = tree.split(/\s+as\s+/);
  if (rest.length || !segmentsValid(path) || (alias !== undefined && !/^\w+$/.test(alias))) {
    return null;
  }
  return { path, alias };
}

/** `name` or `name as alias`. */
function splitAlias(item) {
  const parts = item.split(/\s+as\s+/);
  if (parts.length > 2 || !parts.every((part) => /^\w+$/.test(part))) return null;
  return [parts[0], parts[1]];
}

/**
 * Every `a::b` or `::a` path in the code. A `::` right after the `>` that closes a
 * generic is an associated item, not a crate path; after `->` or `=>` it still counts.
 */
function qualifiedPaths(body) {
  // Join spacing around `::` only between identifiers, so `x: ::a` keeps its own
  // colon and `:: ::a` stays two separators. A raw identifier's `r#` becomes a gap.
  const code = body
    .replace(/\br#/g, " ")
    .replace(/(\w)\s+::/g, "$1::")
    .replace(/::\s+(?=[A-Za-z_])/g, "::");
  const paths = [];
  for (const match of code.matchAll(/(?<![\w:])(?:::)?[A-Za-z_][\w:]*/g)) {
    const path = match[0].replace(/:+$/, "");
    const index = match.index;
    if (!path.includes("::")) continue;
    if (path.startsWith("::") && code[index - 1] === ">" && !"-=".includes(code[index - 2] ?? "")) {
      continue;
    }
    const segments = path.replace(/^::/, "").split("::");
    // A run that isn't a clean path, such as `x:crate::a`, is refused rather than skipped.
    paths.push(segments.every((segment) => IDENTIFIER.test(segment)) ? path : `invalid:${path}`);
  }
  return paths;
}

function hasOnlyFactImports(source, file) {
  if (/\bsitecmd_code_scan\b/.test(source)) {
    return false;
  }
  if (file !== constantsPath && /\bsitecmd_engine\b/.test(source)) {
    return false;
  }
  const names = new Set([
    "Self",
    "String",
    "Vec",
    "Option",
    "Result",
    "Default",
    "str",
    "Box",
    "u32",
    "usize",
  ]);
  for (const definition of source.matchAll(/\b(?:enum|struct|type)\s+(\w+)/g)) {
    names.add(definition[1]);
  }
  let valid = true;
  const useTree = (_, tree) => {
    const normalized = tree.trim().replace(/\s*::\s*/g, "::");
    const parts = parseUseTree(normalized);
    if (!parts) {
      valid = false;
      return "";
    }
    if (parts.members === undefined) {
      valid &&= factPathAllowed(parts.path, file);
      names.add(parts.alias ?? parts.path.split("::").at(-1));
    } else {
      for (const member of parts.members
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)) {
        const imported = splitAlias(member);
        if (!imported) {
          valid = false;
          continue;
        }
        const [name, alias] = imported;
        const path = name === "self" ? parts.path : `${parts.path}::${name}`;
        valid &&= factPathAllowed(path, file);
        names.add(alias ?? path.split("::").at(-1));
      }
    }
    return "";
  };
  const body = source
    .replace(/\bpub\s*\([^)]*\)\s+(use\s+[^;]+;)/g, "pub $1")
    .replace(/\bpub\s+(use\s+[^;]+;)/g, "pub $1")
    .replace(/\b(?:pub )?use\s+([^;]+);/g, useTree)
    .replace(/\bpub\(in crate::core(?:::audit)?\)/g, "");
  return (
    valid &&
    !/\b(?:extern\s+crate|detect_project\s*\(|include\s*!)/.test(body) &&
    !/#\s*\[\s*(?:path\b|cfg_attr\b[^\]]*\bpath\s*=)/.test(body) &&
    qualifiedPaths(body).every((normalized) => {
      return (
        factPathAllowed(normalized, file) ||
        (!normalized.startsWith("::") && names.has(normalized.split("::")[0]))
      );
    })
  );
}

export function codeScanHostBoundaryFailures(read, listFiles) {
  const isModuleFile = (path, base) => path === `${base}.rs` || path.startsWith(`${base}/`);
  const nativeSources = listFiles(native, (path) => path.endsWith(".rs")).map((path) =>
    path.replaceAll("\\", "/"),
  );
  const factPaths = nativeSources.filter((path) =>
    factModules.some((module) => isModuleFile(path, `${native}/${module}`)),
  );
  const hostPaths = nativeSources.filter((path) => isModuleFile(path, sessionHost));
  const sources = new Map(
    [...hostPaths, ...factPaths, constantsPath].map((path) => {
      let code = read(path);
      if (path === `${native}/project_listing.rs`) {
        code = code.replace(
          /^#\[cfg\(test\)\]\n#\[path = "project_listing_tests\.rs"\]\nmod tests;/gm,
          "",
        );
      }
      for (const module of ["engine_io", "git"]) {
        if (path === `${native}/${module}.rs`) {
          code = code.replace(`#[cfg(test)]\n#[path = "${module}_tests.rs"]\nmod tests;`, "");
        }
      }
      return [path, stripNonCode(code, path)];
    }),
  );
  const failures = [];
  for (const path of listFiles(autofix, (file) => file.endsWith(".rs"))) {
    if (privateImports.test(stripNonCode(read(path), path))) {
      failures.push(`Autofix must use public engine host and protocol APIs: ${path}`);
    }
  }
  const boundedHostReaders = ["database_snapshot", "database_targets", "engine_facts", "engine_io"];
  for (const [path, code] of sources) {
    if (!hasOnlyFactImports(code, path)) {
      failures.push(
        `Code Scan host fact imports and qualified paths must use the explicit allowlist: ${path}`,
      );
    }
  }
  const rawReadPaths = [
    ...hostPaths,
    ...factPaths.filter((path) =>
      boundedHostReaders.some((module) => isModuleFile(path, `${native}/${module}`)),
    ),
  ];
  if (
    rawReadPaths.some((path) =>
      /\bfs\s*::\s*(?:read(?:_to_string)?|File\s*::\s*open)\s*\(|\bFile\s*::\s*open\s*\(/.test(
        sources.get(path),
      ),
    )
  ) {
    failures.push("Code Scan host readers must use the shared bounded readers.");
  }
  return failures;
}
