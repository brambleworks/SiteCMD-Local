/**
 * Mirrors apps/desktop/src-tauri/src/cli/audit_suppressions.rs so the MCP view
 * hides exactly the Code Scan findings the CLI and CI hide.
 */

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";

interface SuppressionMatch {
  path?: string;
  rule?: string;
  fingerprint?: string;
}

interface Suppression {
  match: SuppressionMatch;
  reason: string;
  expires?: string;
}

export interface CodeFindingIdentity {
  check_id: string;
  relative_path: string;
  occurrence: string;
}

export interface SuppressibleRow {
  check_id: string;
  source?: string;
  relative_path?: string | null;
  detail_json?: string | null;
}

export interface SuppressedView<T> {
  kept: T[];
  ignored: Array<{ row: T; reason: string }>;
}

/** Same bound as crate::constants::MAX_CLI_CONFIG_BYTES. */
const MAX_CONFIG_BYTES = 64 * 1024;
const CONFIG_VERSION = 1;
const RULE_SHAPE = /^code_scan\.[a-z0-9][a-z0-9-]*$/;
const FINGERPRINT_SHAPE = /^sha256:[0-9a-f]{64}$/;
const EXPIRES_SHAPE = /^(\d{4})-(\d{2})-(\d{2})$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function codeFindingFingerprint(identity: CodeFindingIdentity): string {
  const occurrence = identity.occurrence.split(/\s+/).filter(Boolean).join(" ");
  const material = [
    "sitecmd-code-finding-v1",
    identity.check_id,
    identity.relative_path.replace(/\\/g, "/"),
    occurrence,
  ].join("\0");
  return `sha256:${createHash("sha256").update(material, "utf8").digest("hex")}`;
}

const SEPARATOR = "/";

/**
 * `*`, `?` and `**` are the only metacharacters this subset understands.
 * Everything else, brackets and braces included, is a literal character.
 */
type GlobToken =
  | { kind: "literal"; character: string }
  | { kind: "oneCharacter" } // `?`: one character that is not a separator.
  | { kind: "segmentRun" } // `*`: any run of characters within one segment.
  | { kind: "pathRun" } // `**`: any run of characters, separators included.
  | { kind: "descendantPrefix" }; // `**/`: nothing, or any run ending in a separator.

function tokenizeGlob(body: string): GlobToken[] {
  const tokens: GlobToken[] = [];
  for (let index = 0; index < body.length; index += 1) {
    const character = body[index];
    if (character === "*" && body[index + 1] === "*") {
      const swallowsSeparator = body[index + 2] === SEPARATOR;
      tokens.push({ kind: swallowsSeparator ? "descendantPrefix" : "pathRun" });
      index += swallowsSeparator ? 2 : 1;
    } else if (character === "*") {
      tokens.push({ kind: "segmentRun" });
    } else if (character === "?") {
      tokens.push({ kind: "oneCharacter" });
    } else {
      tokens.push({ kind: "literal", character });
    }
  }
  return tokens;
}

/**
 * Advances every candidate offset at once instead of backtracking, so chained
 * `**` cannot blow up: the work is bounded by token count times path length.
 * `reached[offset]` means some prefix of the tokens consumed the path up to
 * `offset` from one of the permitted start offsets.
 */
function matchesGlobTokens(tokens: GlobToken[], path: string, anchored: boolean): boolean {
  const end = path.length;
  let reached = new Uint8Array(end + 1);
  let next = new Uint8Array(end + 1);
  reached[0] = 1;
  // An unanchored pattern may also begin at the start of any inner segment.
  if (!anchored) {
    for (let offset = 0; offset < end; offset += 1) {
      if (path[offset] === SEPARATOR) reached[offset + 1] = 1;
    }
  }

  for (const token of tokens) {
    switch (token.kind) {
      case "literal": {
        next.fill(0);
        for (let offset = 0; offset < end; offset += 1) {
          if (reached[offset] && path[offset] === token.character) next[offset + 1] = 1;
        }
        break;
      }
      case "oneCharacter": {
        next.fill(0);
        for (let offset = 0; offset < end; offset += 1) {
          if (reached[offset] && path[offset] !== SEPARATOR) next[offset + 1] = 1;
        }
        break;
      }
      case "segmentRun": {
        let open = 0;
        for (let offset = 0; offset <= end; offset += 1) {
          if (reached[offset]) open = 1;
          next[offset] = open;
          if (path[offset] === SEPARATOR) open = 0; // the run cannot cross a separator
        }
        break;
      }
      case "pathRun": {
        let open = 0;
        for (let offset = 0; offset <= end; offset += 1) {
          if (reached[offset]) open = 1;
          next[offset] = open;
        }
        break;
      }
      case "descendantPrefix": {
        next.set(reached); // `**/` is optional, so it may consume nothing
        let open = 0;
        for (let offset = 0; offset < end; offset += 1) {
          if (reached[offset]) open = 1;
          if (open && path[offset] === SEPARATOR) next[offset + 1] = 1;
        }
        break;
      }
    }
    const spent = reached;
    reached = next;
    next = spent;
    if (!reached.includes(1)) return false;
  }

  // The pattern has to land on a separator or the end of the path, which is what
  // makes a match on a directory cover everything beneath it.
  for (let offset = 0; offset <= end; offset += 1) {
    if (reached[offset] && (offset === end || path[offset] === SEPARATOR)) return true;
  }
  return false;
}

/** gitignore subset: leading or inner slash anchors, `**` spans directories, a match on a directory covers its children. */
export function pathMatchesSuppression(pattern: string, relativePath: string): boolean {
  let body = pattern.startsWith(SEPARATOR) ? pattern.slice(1) : pattern;
  if (body.endsWith(SEPARATOR)) body = body.slice(0, -1);
  const anchored = pattern.startsWith(SEPARATOR) || body.includes(SEPARATOR);
  return matchesGlobTokens(tokenizeGlob(body), relativePath.replace(/\\/g, SEPARATOR), anchored);
}

function validated(index: number, raw: unknown): Suppression {
  const label = `Code Scan suppression ${index + 1}`;
  if (!isRecord(raw) || !isRecord(raw.match)) {
    throw new Error(`${label} must be an object with a match object`);
  }
  const reason = typeof raw.reason === "string" ? raw.reason.trim() : "";
  if (reason.length === 0) throw new Error(`${label} requires a non-empty reason`);
  const trimmed = (value: unknown): string | undefined =>
    typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
  const match: SuppressionMatch = {
    path: trimmed(raw.match.path),
    rule: trimmed(raw.match.rule),
    fingerprint: trimmed(raw.match.fingerprint),
  };
  if (!match.path && !match.rule && !match.fingerprint) {
    throw new Error(`${label} must match a path, rule, or fingerprint`);
  }
  if (match.path && (isAbsolute(match.path) || match.path.split(/[\\/]/).includes(".."))) {
    throw new Error(`${label} path must be project-relative and cannot contain '..'`);
  }
  if (match.rule && !RULE_SHAPE.test(match.rule)) {
    throw new Error(`${label} rule must be an exact canonical code_scan.* check ID`);
  }
  if (match.fingerprint && !FINGERPRINT_SHAPE.test(match.fingerprint)) {
    throw new Error(
      `${label} fingerprint must be sha256 followed by 64 lowercase hexadecimal characters`,
    );
  }
  const expires = typeof raw.expires === "string" ? raw.expires : undefined;
  if (expires !== undefined && !EXPIRES_SHAPE.test(expires)) {
    throw new Error(`${label} has invalid expires date '${expires}'; use YYYY-MM-DD`);
  }
  return { match, reason, expires };
}

// One descriptor carries the size check and the read, so the bytes parsed are
// the bytes measured. Checking a path and then reopening it describes two
// different moments, and the budget is only worth the guarantee that both saw
// the same file. A missing config is an absent file, not an error.
function readConfigWithinBudget(configPath: string): string | null {
  let handle: number;
  try {
    handle = openSync(configPath, constants.O_RDONLY);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return null;
    throw error;
  }
  try {
    const opened = fstatSync(handle);
    if (!opened.isFile()) return null;
    if (opened.size > MAX_CONFIG_BYTES) {
      throw new Error(`${configPath} is too large (maximum ${MAX_CONFIG_BYTES} bytes)`);
    }
    return readFileSync(handle, "utf8");
  } finally {
    closeSync(handle);
  }
}

function loadRepoSuppressions(projectPath: string): Suppression[] {
  const configPath = join(projectPath, ".sitecmd", "config.json");
  const contents = readConfigWithinBudget(configPath);
  if (contents === null) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch (error) {
    throw new Error(
      `failed to parse ${configPath}: ${error instanceof Error ? error.message : String(error)}`,
      { cause: error },
    );
  }
  if (!isRecord(parsed))
    throw new Error(`failed to parse ${configPath}: top level must be an object`);
  if (parsed.version !== CONFIG_VERSION) {
    throw new Error(
      `unsupported .sitecmd/config.json version ${String(parsed.version)}; expected ${CONFIG_VERSION}`,
    );
  }
  const codeScan = isRecord(parsed.code_scan) ? parsed.code_scan : {};
  const raw = Array.isArray(codeScan.suppressions) ? codeScan.suppressions : [];
  return raw.map((entry, index) => validated(index, entry));
}

function isExpired(suppression: Suppression, today: Date): boolean {
  if (!suppression.expires) return false;
  return (
    Date.parse(`${suppression.expires}T00:00:00.000Z`) <
    Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate())
  );
}

/** Persisted detail_json is the CodeIssue struct serialized with #[serde(rename_all = "camelCase")]; accept either casing so both freshly-scanned and legacy rows resolve. */
function stringField(
  detail: Record<string, unknown>,
  snakeCase: string,
  camelCase: string,
): string | undefined {
  const value = detail[snakeCase] ?? detail[camelCase];
  return typeof value === "string" ? value : undefined;
}

function identityOf(row: SuppressibleRow): CodeFindingIdentity | null {
  if (row.source !== "code_scan" || !row.detail_json) return null;
  let detail: unknown;
  try {
    detail = JSON.parse(row.detail_json);
  } catch {
    return null;
  }
  if (!isRecord(detail)) return null;
  const relativePath =
    stringField(detail, "relative_path", "relativePath") ?? row.relative_path ?? null;
  if (!relativePath) return null;
  const occurrence = [
    stringField(detail, "source_excerpt", "sourceExcerpt"),
    stringField(detail, "evidence", "evidence"),
    stringField(detail, "id", "id"),
  ].find((value): value is string => typeof value === "string");
  if (occurrence === undefined) return null;
  return { check_id: row.check_id, relative_path: relativePath, occurrence };
}

function matches(
  suppression: Suppression,
  identity: CodeFindingIdentity,
  fingerprint: string,
): boolean {
  const { rule, fingerprint: expected, path } = suppression.match;
  return (
    (rule === undefined || rule === identity.check_id) &&
    (expected === undefined || expected === fingerprint) &&
    (path === undefined || pathMatchesSuppression(path, identity.relative_path))
  );
}

export function applyRepoSuppressions<T extends SuppressibleRow>(
  projectPath: string | null,
  rows: T[],
  today: Date,
): SuppressedView<T> {
  if (!projectPath) return { kept: rows, ignored: [] };
  const suppressions = loadRepoSuppressions(projectPath).filter(
    (entry) => !isExpired(entry, today),
  );
  if (suppressions.length === 0) return { kept: rows, ignored: [] };
  const kept: T[] = [];
  const ignored: Array<{ row: T; reason: string }> = [];
  for (const row of rows) {
    const identity = identityOf(row);
    if (!identity) {
      kept.push(row);
      continue;
    }
    const fingerprint = codeFindingFingerprint(identity);
    const hit = suppressions.find((entry) => matches(entry, identity, fingerprint));
    if (hit) ignored.push({ row, reason: hit.reason });
    else kept.push(row);
  }
  return { kept, ignored };
}
