import { posix, win32 } from "node:path";
import { stripComments, stripNonCode } from "./guardrail-source-text.mjs";
import { ENGINE_CRATES, enginePathFailures } from "./publication-history-rules.mjs";
import { tomlFields } from "./toml-fields.mjs";

export const RUST_WORKSPACE = "apps/desktop/src-tauri";
const PROTOCOL = `${RUST_WORKSPACE}/crates/protocol`;
const ENGINE_HOST = `${RUST_WORKSPACE}/crates/engine-host`;
const SOURCE_FILES = new Set([
  "agent.rs",
  "brief_copy.rs",
  "code_domain.rs",
  "code_scan.rs",
  "code_scan/abi.rs",
  "coverage.rs",
  "database_env.rs",
  "engine_abi/fixes.rs",
  "engine_abi/frame.rs",
  "engine_abi/guest.rs",
  "engine_abi/local_site_wire.rs",
  "engine_abi/mod.rs",
  "engine_abi/types.rs",
  "engine_abi/wire_tests.rs",
  "header_lines.rs",
  "identity.rs",
  "lib.rs",
  "log_sanitizer.rs",
  "log_sanitizer/authorization_tests.rs",
  "log_sanitizer/basic.rs",
  "log_sanitizer/basic_body_tests.rs",
  "log_sanitizer/bearer_encoding_tests.rs",
  "log_sanitizer/counted_regex.rs",
  "log_sanitizer/credential_tests.rs",
  "log_sanitizer/literal.rs",
  "log_sanitizer/literal_test_support.rs",
  "log_sanitizer/login_mask_tests.rs",
  "log_sanitizer/mask.rs",
  "log_sanitizer/path_credentials.rs",
  "log_sanitizer/path_safety_tests.rs",
  "log_sanitizer/pem.rs",
  "log_sanitizer/pem_comment_tests.rs",
  "log_sanitizer/provider_tokens.rs",
  "log_sanitizer/provider_tokens/evidence.rs",
  "log_sanitizer/route_token_tests.rs",
  "log_sanitizer/shared_test_support.rs",
  "log_sanitizer/test_support.rs",
  "log_sanitizer/unicode_boundary_tests.rs",
  "log_sanitizer/url_encoding_tests.rs",
  "manifest.rs",
  "network_class.rs",
  "page.rs",
  "project_paths.rs",
  "release.rs",
  "route.rs",
  "route/tests.rs",
  "score.rs",
  "skipped_scopes.rs",
  "stack.rs",
  "storable.rs",
  "sync/fingerprint.rs",
  "sync/fingerprint_tests.rs",
  "sync/mod.rs",
  "sync/payload.rs",
  "sync/payload_tests.rs",
  "sync/snapshot.rs",
  "sync/snapshot_tests.rs",
  "sync/wire.rs",
  "sync/wire_grammar.rs",
  "sync/wire_tests.rs",
  "time.rs",
  "time/date.rs",
  "time/format.rs",
  "time/parse.rs",
  "url_path.rs",
  "vocab.rs",
]);
const MODULES = new Set([
  "agent",
  "brief_copy",
  "code_domain",
  "code_scan",
  "coverage",
  "database_env",
  "engine_abi",
  "header_lines",
  "identity",
  "log_sanitizer",
  "manifest",
  "network_class",
  "page",
  "project_paths",
  "release",
  "route",
  "score",
  "skipped_scopes",
  "stack",
  "storable",
  "sync",
  "time",
  "url_path",
  "vocab",
]);
export function isPrivateRustPath(file) {
  return (
    file.toLowerCase().startsWith(`${RUST_WORKSPACE}/`) && enginePathFailures([file]).length > 0
  );
}

export function publicRustSources(listFiles) {
  return listFiles(RUST_WORKSPACE, (file) => file.endsWith(".rs") && !isPrivateRustPath(file));
}

const DEPENDENCY_SECTION = /^(?:dependencies|(?:build|dev)[-_]dependencies)$/;
const SOURCE_PATH = /^(?:r(#*)"([^"]*)"\1|"([^"\\]*)")(?=\s*[,)}\]])/;
const STORAGE_TYPE = String.raw`(?:r#)?(?:DiscoveryResponse|SitemapRoutes)\b(?:\s+as\s+(?:r#)?\w+)?`;
const STORAGE_TYPES = new RegExp(
  String.raw`^\s*(?:${STORAGE_TYPE}|\{\s*${STORAGE_TYPE}(?:\s*,\s*${STORAGE_TYPE})*\s*,?\s*\})`,
);

function localSourcePath(file, argument) {
  const literal = SOURCE_PATH.exec(argument.trimStart());
  if (!literal) return false;
  const path = literal[2] ?? literal[3];
  if (!path || posix.isAbsolute(path) || win32.isAbsolute(path) || /[\\:\0]/.test(path)) {
    return false;
  }
  return posix.join(posix.dirname(file), path).startsWith(`${PROTOCOL}/`);
}

function sourcePathFailures(file, source, code) {
  const failures = [];
  const commentsBlanked = stripComments(source, file);
  const includeFailure = `${file} - include! must use a literal path inside the protocol crate.`;
  if (/\binclude\s+as\b/.test(code)) failures.push(includeFailure);
  function checkPath(kind, start) {
    if (!localSourcePath(file, commentsBlanked.slice(start))) {
      failures.push(`${file} - ${kind} must use a literal path inside the protocol crate.`);
    }
  }
  for (const match of code.matchAll(/\binclude\s*!\s*[({[]/g)) {
    checkPath("include!", match.index + match[0].length);
  }
  for (const match of code.matchAll(/#\s*!?\s*\[[^\]]*\]/g)) {
    for (const attribute of match[0].matchAll(/[[,(]\s*(?:r#)?path\s*=/g)) {
      checkPath("path attribute", match.index + attribute.index + attribute[0].length);
    }
  }
  return failures;
}

function usesProtocolStorageGate(code) {
  // Restrict imports as well as calls so the gate cannot be called through an alias.
  for (const match of code.matchAll(/\bstorable\s*::/g)) {
    if (!STORAGE_TYPES.test(code.slice(match.index + match[0].length))) return true;
  }
  return /\bstorable\s+as\b/.test(code);
}

function privateWorkspaceAliases(source, read) {
  const inheritedAliases = tomlFields(source).filter(({ path, value }) => {
    const [section, , key] = path.slice(-3);
    const dependency = path.length === 3 || (path.length === 5 && path[0] === "target");
    return (
      dependency && DEPENDENCY_SECTION.test(section) && key === "workspace" && value === "true"
    );
  });
  if (inheritedAliases.length === 0) return [];

  const privateAliases = new Set();
  const workspace = read(`${RUST_WORKSPACE}/Cargo.toml`) ?? "";
  for (const { path, value } of tomlFields(workspace)) {
    if (
      path.length === 4 &&
      path[0] === "workspace" &&
      path[1] === "dependencies" &&
      path[3] === "package" &&
      ENGINE_CRATES.includes(value)
    ) {
      privateAliases.add(path[2]);
    }
  }
  return new Set(
    inheritedAliases.map(({ path }) => path.at(-2)).filter((alias) => privateAliases.has(alias)),
  );
}

function privateDependencyFailures(crate, label, read) {
  const file = `${crate}/Cargo.toml`;
  const source = read(file) ?? "";
  const failures = [];
  for (const name of ENGINE_CRATES) {
    if (new RegExp(`(?<![\\w-])${name}(?![\\w-])`).test(source)) {
      failures.push(`${file} - private ${label} dependency: ${name}.`);
    }
  }
  for (const alias of privateWorkspaceAliases(source, read)) {
    failures.push(`${file} - private ${label} dependency through workspace alias: ${alias}.`);
  }
  return failures;
}

function engineHostDependencyFailures(read) {
  const file = `${ENGINE_HOST}/Cargo.toml`;
  const dependencies = new Map();
  for (const { path, value } of tomlFields(read(file) ?? "")) {
    const relative = path[0] === "target" ? path.slice(2) : path;
    const [section, alias, field] = relative;
    if (!DEPENDENCY_SECTION.test(section) || !alias) continue;
    const key = path.slice(0, path[0] === "target" ? 4 : 2).join("\0");
    if (!dependencies.has(key)) dependencies.set(key, { alias });
    if (field) dependencies.get(key)[field] = value;
  }

  const failures = [];
  for (const dependency of dependencies.values()) {
    const { alias, package: name = alias, path, registry } = dependency;
    const cratesIo = path === undefined && (registry === undefined || registry === "crates-io");
    const protocol =
      name === "sitecmd-protocol" && path === "../protocol" && registry === undefined;
    if (
      (!cratesIo && !protocol) ||
      ENGINE_CRATES.includes(name) ||
      ["workspace", "git", "registry-index"].some((field) => Object.hasOwn(dependency, field))
    ) {
      failures.push(
        `${file} - engine-host dependency must use crates.io or the protocol path: ${alias}.`,
      );
    }
  }
  return failures;
}

// Rust web and code findings can lose confidence metadata or its serde default.
export function issueConfidenceFailures(read) {
  const rustCheckTypes = read(`${PROTOCOL}/src/vocab.rs`);
  const carriesConfidence =
    rustCheckTypes.includes("pub enum IssueConfidence") &&
    rustCheckTypes.includes("#[serde(default)]\n    pub confidence: IssueConfidence") &&
    rustCheckTypes.includes("pub confidence: IssueConfidence") &&
    rustCheckTypes.includes("pub confidence_reason: Option<String>");
  return carriesConfidence
    ? []
    : [
        "Rust web/code issue payloads must carry confidence fields so new issues intentionally inherit or set confidence.",
      ];
}

export function protocolContentsFailures(read, listFiles) {
  const failures = [
    ...privateDependencyFailures(PROTOCOL, "protocol", read),
    ...engineHostDependencyFailures(read),
  ];
  for (const file of listFiles(PROTOCOL, () => true)) {
    const source = read(file);
    if (file.includes("key_patterns") || source.includes("key_patterns")) {
      failures.push(`${file} - private table name in protocol source.`);
    }
    const inSource = file.startsWith(`${PROTOCOL}/src/`);
    const relative = file.slice(`${PROTOCOL}/src/`.length);
    if (inSource && !SOURCE_FILES.has(relative)) {
      failures.push(`${file} - unlisted protocol source file: ${relative}.`);
    }
    if (!file.endsWith(".rs")) continue;
    const code = stripNonCode(source, file);
    failures.push(...sourcePathFailures(file, source, code));
    if (!inSource || relative !== "lib.rs") continue;
    const names = [...code.matchAll(/\bmod\s+(?:r#)?(\w+)\s*[;{]/g)].map((match) => match[1]);
    for (const name of new Set(names)) {
      if (!MODULES.has(name)) failures.push(`${file} - unlisted protocol module: ${name}.`);
    }
  }
  const storageCallers = publicRustSources(listFiles);
  return [...failures, ...storageGateFailures(read, storageCallers)];
}

export function storageGateFailures(read, files) {
  const failures = [];
  for (const file of files) {
    const source = read(file);
    if (!source.includes("storable")) continue;
    const code = stripNonCode(source, file);
    const callsWithinProtocol =
      file.startsWith(`${PROTOCOL}/`) &&
      /\bstorable\s*\(/.test(code.replace(/\bfn\s+storable\b/g, ""));
    if (callsWithinProtocol || usesProtocolStorageGate(code)) {
      failures.push(`${file} - only the engine may access the protocol storage gate.`);
    }
  }
  return failures;
}
