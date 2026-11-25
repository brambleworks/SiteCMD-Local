export function functionBodyContains(source, fnName, needle) {
  const escapedName = fnName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const signatures = new RegExp(
    `(?:(?:pub(?:\\([^)]*\\))?\\s+)?(?:async\\s+)?fn|(?:export\\s+)?(?:async\\s+)?function)\\s+${escapedName}\\b`,
    "g",
  );
  for (const signature of source.matchAll(signatures)) {
    const tailStart = signature.index + signature[0].length;
    const boundary = source.slice(tailStart).search(/[;{]/);
    if (boundary === -1 || source[tailStart + boundary] === ";") continue;
    const bodyStart = tailStart + boundary;
    let depth = 0;
    for (let cursor = bodyStart; cursor < source.length; cursor += 1) {
      const ch = source[cursor];
      if (ch === "{") {
        depth += 1;
      } else if (ch === "}") {
        depth -= 1;
        if (depth === 0) {
          if (source.slice(bodyStart, cursor).includes(needle)) return true;
          break;
        }
      }
    }
  }
  return false;
}

// Extract a Rust function through its matching closing brace.
export function rustFunctionBody(source, name) {
  const start = source.search(new RegExp(`fn ${name}\\b`));
  if (start === -1) return null;
  const open = source.indexOf("{", start);
  if (open === -1) return null;
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(open, index + 1);
    }
  }
  return null;
}
