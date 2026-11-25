// Resolve wire leaves to definitions before granting a reviewed serializer trust.
const BASE = "apps/desktop/src-tauri/";
export function closing(source, start, open = "{", shut = "}") {
  let depth = 1;
  for (let end = start; end < source.length; end++) {
    if (source[end] === open) depth++;
    if (source[end] === shut && --depth === 0) return end;
  }
  return source.length;
}
function splitTypes(source) {
  const parts = [];
  let depth = 0,
    start = 0;
  for (let i = 0; i < source.length; i++) {
    if ("({[<".includes(source[i])) depth++;
    if (")}]>".includes(source[i])) depth--;
    if (source[i] === "," && depth === 0) {
      parts.push(source.slice(start, i));
      start = i + 1;
    }
  }
  return [...parts, source.slice(start)].filter((part) => part.trim());
}
function fileModule(file, extraRoots) {
  const protocol = `${BASE}crates/protocol/src/`;
  const [root, prefix] = [
    ...extraRoots,
    [protocol, "sitecmd_protocol"],
    [`${BASE}src/`, "sitecmd_runtime"],
  ].find(([root]) => file.startsWith(root)) ?? [`${BASE}src/`, "sitecmd_runtime"];
  const path = file
    .slice(root.length)
    .replace(/\.rs$/, "")
    .replace(/\/(?:mod|lib)$/, "");
  return prefix + (["lib", "runtime"].includes(path) ? "" : `::${path.replaceAll("/", "::")}`);
}
function imports(tree, prefix = "") {
  return splitTypes(tree).flatMap((part) => {
    const brace = part.indexOf("{");
    if (brace >= 0)
      return imports(
        part.slice(brace + 1, part.lastIndexOf("}")),
        prefix + part.slice(0, brace).trim(),
      );
    const [path, alias] = part.trim().split(/\s+as\s+/);
    return [{ path: prefix + path, name: alias ?? path.split("::").at(-1) }];
  });
}
export function wireIndex(sources, extraRoots = []) {
  const contexts = [],
    definitions = new Map();
  function collect(file, module, source) {
    const nested = [];
    for (const match of source.matchAll(/\bmod\s+(\w+)\s*\{/g)) {
      const start = match.index + match[0].length;
      const end = closing(source, start);
      if (nested.some(([from, to]) => match.index >= from && match.index < to)) continue;
      collect(file, `${module}::${match[1]}`, source.slice(start, end));
      nested.push([match.index, end + 1]);
    }
    for (const [from, to] of nested.reverse())
      source = source.slice(0, from) + " ".repeat(to - from) + source.slice(to);
    const context = { file, module, source, imports: [] };
    for (const match of source.matchAll(/\buse\s+([^;]+);/g))
      context.imports.push(...imports(match[1]));
    contexts.push(context);
    for (const match of source.matchAll(/\b(struct|enum|type)\s+(\w+)([^;{]*)([;{])/g)) {
      const start = match.index + match[0].length;
      let head = source
        .slice(0, match.index)
        .replace(/pub(?:\([^)]*\)|)\s*$/, "")
        .trimEnd();
      const attributes = [];
      while (head.endsWith("]")) {
        let depth = 1,
          open = head.length - 2;
        for (; open >= 0; open--) {
          if (head[open] === "]") depth++;
          if (head[open] === "[" && --depth === 0) break;
        }
        if (head[open - 1] !== "#") break;
        attributes.unshift(head.slice(open - 1));
        head = head.slice(0, open - 1).trimEnd();
      }
      const attrs = attributes.join("\n");
      const body = match[4] === "{" ? source.slice(start, closing(source, start)) : match[3];
      const key = `${module}::${match[2]}`;
      const declaration = {
        ...context,
        key,
        name: match[2],
        kind: match[1],
        body,
        attrs,
        serializable: /derive\([^)]*\bSerialize\b/.test(attrs),
      };
      if (definitions.has(key)) declaration.ambiguous = true;
      definitions.set(key, declaration);
    }
  }
  for (const [file, source] of sources) collect(file, fileModule(file, extraRoots), source);
  function absolute(path, module) {
    if (path.startsWith("crate::")) return module.split("::")[0] + path.slice(5);
    if (path.startsWith("self::")) return module + path.slice(4);
    while (path.startsWith("super::")) {
      module = module.split("::").slice(0, -1).join("::");
      path = path.slice(7);
    }
    const local = `${module}::${path}`;
    if (
      definitions.has(local) ||
      contexts.some((item) => item.module === `${module}::${path.split("::")[0]}`)
    )
      return local;
    return [
      "sitecmd_protocol",
      "sitecmd_runtime",
      "std",
      "core",
      "alloc",
      ...extraRoots.map(([, name]) => name),
    ].includes(path.split("::")[0])
      ? path
      : `${module}::${path}`;
  }
  function resolve(path, context, seen = new Set()) {
    const key = absolute(path, context.module);
    if (seen.has(key)) return key;
    seen.add(key);
    const first = path.split("::")[0];
    const imported = context.imports.filter((item) => item.name === first);
    if (imported.length === 1) {
      const target = imported[0].path + path.slice(first.length);
      return resolve(
        target,
        { ...context, imports: context.imports.filter((item) => item !== imported[0]) },
        seen,
      );
    }
    if (definitions.has(key)) return key;
    // Follow public re-exports at the target module as well as direct imports.
    const at = key.lastIndexOf("::");
    const target = contexts.find((item) => item.module === key.slice(0, at));
    if (target) {
      const leaf = key.slice(at + 2);
      for (const item of target.imports) {
        if (item.name === leaf) return resolve(item.path, target, seen);
        if (item.name === "*") {
          const candidate = resolve(`${item.path.slice(0, -1)}${leaf}`, target, new Set(seen));
          if (definitions.has(candidate)) return candidate;
        }
      }
    }
    return key;
  }
  return { contexts, definitions, resolve };
}
export function wireFields(declaration) {
  let body = declaration.body.replace(/#\[[\s\S]*?\]/g, "");
  let records = [body];
  if (declaration.kind === "enum")
    records = splitTypes(body).map((variant) => variant.replace(/^\s*\w+\s*/, ""));
  return records.flatMap((record) => {
    record = record.trim();
    if (!record) return [];
    if ("({".includes(record[0])) record = record.slice(1, -1);
    return splitTypes(record).map((field) => {
      const named = field.match(/^\s*(?:pub(?:\([^)]*\)|)\s+|)(\w+)\s*:(?!:)\s*([\s\S]*)$/);
      return { name: named?.[1], type: named?.[2] ?? field.replace(/\bpub(?:\([^)]*\)|)\s*/g, "") };
    });
  });
}
