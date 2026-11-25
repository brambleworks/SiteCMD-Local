// Unchecked request bodies and transitive serializers could send customer text.
import { createHash } from "node:crypto";
import { wireIndex, wireFields, closing } from "./guardrail-rust-wire-index.mjs";
import { stripComments } from "./guardrail-source-text.mjs";
import { RUST_WORKSPACE } from "./guardrail-protocol-contents-rules.mjs";

const BASE = `${RUST_WORKSPACE}/`;
const primitives = new Set("bool u8 u16 u32 u64 i64 f64 Option Vec".split(" "));
const localOnly = new Set("summary tool_output stdout stderr source_line".split(" "));
const digest = (source) => createHash("sha256").update(source).digest("hex");
// These reviewed serializers are the only private string storage on the wire.
const trusted = new Map([
  [
    `${BASE}src/connected_service/request_body.rs`,
    "bb8c47a853ab052c7b05caf4b3ef50e0fd69ff52da02f8e83f91b90fd99fa797",
  ],
  [
    `${BASE}crates/protocol/src/sync/wire.rs`,
    "d6daa05386e5401ff4e9f239ebf003ef726627a6dbab05a151ac515f6b8bcec0",
  ],
  [
    `${BASE}crates/protocol/src/sync/wire_grammar.rs`,
    "995a0f9799e29458cb66672b7f5cd7b94ace8b79278a88d9c3624f0b09fb23b6",
  ],
  [
    `${BASE}crates/protocol/src/manifest.rs`,
    "34db66666bb0483d33fa13619b673ed6a8de21780915385d3624bb390f852776",
  ],
  [
    `${BASE}crates/protocol/src/route.rs`,
    "c19799c60d8639f1ca6e158bf3e9fee96b3f3c64468f116b9338d0b774efb917",
  ],
]);
function isWirePath(type) {
  return type.split("::").every((part) => /^\w+$/.test(part));
}
function hasOpaqueField(type) {
  const bracket = type.indexOf("[");
  if (
    /\b(?:String|str|Value|HashMap|Map)\b/.test(type) ||
    (bracket >= 0 && type.indexOf("]", bracket + 1) >= 0)
  )
    return true;
  const vectors = /\bVec\s*<\s*/g;
  const wrapper = /(?:Option|Vec)\s*<\s*/y;
  const numeric = /(?:[uif]\d+|bool)\b/y;
  while (vectors.exec(type)) {
    let end = vectors.lastIndex;
    wrapper.lastIndex = end;
    while (wrapper.exec(type)) {
      end = wrapper.lastIndex;
    }
    numeric.lastIndex = end;
    if (numeric.test(type)) return true;
    vectors.lastIndex = end;
  }
  return false;
}
function typePaths(type) {
  const paths = [];
  let start = -1,
    end = -1;
  for (const match of type.matchAll(/[A-Za-z_]\w*/g)) {
    if (end < 0 || type.slice(end, match.index) !== "::") {
      if (start >= 0) paths.push(type.slice(start, end));
      start = match.index;
    }
    end = match.index + match[0].length;
  }
  if (start >= 0) paths.push(type.slice(start, end));
  return paths;
}
export function connectedRequestFailures(files, read, extraRoots) {
  const failures = [];
  const sources = new Map(
    files
      .filter((file) => file.endsWith(".rs") && !/tests?\.rs$/.test(file))
      .map((file) => {
        let source = stripComments(read(file), file);
        const tests =
          /#\[cfg\(test\)\]\s*(?:#\[path[^\n]+\]\s*|)(?:pub(?:\([^)]*\)|)\s+|)mod\s+\w+\s*([;{])/g;
        for (const match of [...source.matchAll(tests)].reverse()) {
          const start = match.index + match[0].length;
          const end = match[1] === "{" ? closing(source, start) + 1 : start;
          source = source.slice(0, match.index) + source.slice(end);
        }
        return [file, source];
      }),
  );
  const index = wireIndex(sources, extraRoots);
  const leaves = new Set();
  for (const context of index.contexts) {
    if (!trusted.has(context.file)) continue;
    const source = sources.get(context.file);
    if (digest(source) !== trusted.get(context.file))
      failures.push(
        `${context.file}: constrained serializer changed; audit its storage, validation, and wire projection`,
      );
    if (context.file.endsWith("/route.rs")) leaves.add(`${context.module}::CanonicalRoute`);
    if (context.file.endsWith("/wire.rs") || context.file.endsWith("/manifest.rs")) {
      for (const match of source.matchAll(/wire_value!\(\s*(\w+)/g)) {
        const key = `${context.module}::${match[1]}`;
        leaves.add(key);
        index.definitions.set(key, { ...context, key, name: match[1], trusted: true });
      }
    }
  }
  const leafNames = new Set([...leaves].map((key) => key.split("::").at(-1)));
  const roots = [];
  for (const context of index.contexts) {
    const { source, file } = context;
    const client =
      /impl\s+ConnectedServiceClient\b/.test(source) ||
      (source.includes("ConnectedServiceClient") &&
        /\.(?:request|request_with_github_oidc)\s*\(/.test(source));
    for (const match of source.matchAll(/\bimpl\b[^{};]*?\bWireRequest\s+for\s+([^{}]+)\s*\{/g)) {
      const type = match[1].trim();
      const key = index.resolve(type, context);
      const declaration = index.definitions.get(key);
      if (!isWirePath(type) || !declaration || !["struct", "enum"].includes(declaration.kind))
        failures.push(`${file}: WireRequest root ${type} must be a declared struct or enum`);
      else roots.push(declaration);
    }
    if (client && /\bjson!\s*\(/.test(source))
      failures.push(`${file}: untyped JSON request bypasses wire types`);
    if (!trusted.has(file)) {
      for (const match of source.matchAll(/impl[^{};]*\bSerialize\s+for\s+([^{}]+)/g)) {
        const type = match[1].trim().split(/\s|</)[0];
        if (client || type.includes("$") || leafNames.has(type.split("::").at(-1)))
          failures.push(`${file}: unaudited custom request serializer for ${type}`);
      }
    }
    if (client)
      for (const declaration of index.definitions.values()) {
        if (declaration.file === file && declaration.serializable) roots.push(declaration);
      }
  }
  const visited = new Set();
  function audit(declaration, parent) {
    if (declaration.ambiguous) {
      failures.push(`${parent}: ambiguous audited wire type ${declaration.key}`);
      return;
    }
    if (leaves.has(declaration.key)) return;
    if (visited.has(declaration.key)) return;
    visited.add(declaration.key);
    const { file, name, attrs, body } = declaration;
    if (!declaration.serializable || declaration.kind === "type") {
      failures.push(`${parent}: uses unaudited wire type ${declaration.key}`);
      return;
    }
    if (/serialize_with\s*=|serde\([^)]*\b(?:with|into|try_from)\s*=/.test(body + attrs))
      failures.push(`${file}: ${name} overrides its wire serializer`);
    for (const field of wireFields(declaration)) {
      const label = `${file}: ${name}${field.name ? `.${field.name}` : ""}`;
      if (localOnly.has(field.name)) failures.push(`${label} is local-only data`);
      const type = field.type.replace(/'\w+/g, "");
      if (hasOpaqueField(type))
        failures.push(`${label} contains free text or an opaque numeric array`);
      const paths = typePaths(type);
      const names = paths.map((path) => path.split("::").at(-1));
      if (names.includes("Vec") && names.every((name) => primitives.has(name)))
        failures.push(`${label} contains an opaque numeric collection`);
      for (const path of paths) {
        const key = index.resolve(path, declaration);
        const nested = index.definitions.get(key);
        if (nested) audit(nested, label);
        else if (
          !(primitives.has(path) && !declaration.imports.some((item) => item.name === path)) &&
          !/^(?:std|core|alloc)::(?:option::Option|vec::Vec)$/.test(path)
        )
          failures.push(`${label}: uses unaudited wire type ${path}`);
      }
    }
  }
  for (const root of roots) audit(root, root.key);
  return failures;
}
