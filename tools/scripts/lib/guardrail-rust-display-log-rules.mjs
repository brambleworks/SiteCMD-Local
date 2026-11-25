const RUST_SRC_DIRS = ["apps/desktop/src-tauri/src"];

// Find real instrument attributes, including multiline and stacked attributes.
function instrumentedFnNames(source) {
  const names = new Set();
  const lines = source.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    if (!lines[i].trimStart().startsWith("#[tracing::instrument")) continue;
    let depth = 0;
    let attrEnd = i;
    let closed = false;
    for (let j = i; j < lines.length && !closed; j += 1) {
      for (const ch of lines[j]) {
        if (ch === "[") depth += 1;
        else if (ch === "]") {
          depth -= 1;
          if (depth === 0) {
            attrEnd = j;
            closed = true;
            break;
          }
        }
      }
    }
    for (let k = attrEnd + 1; k < lines.length && k <= attrEnd + 6; k += 1) {
      const trimmed = lines[k].trim();
      if (trimmed === "" || trimmed.startsWith("#[")) continue;
      const fn = trimmed.match(/^(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)/);
      if (fn) names.add(fn[1]);
      break;
    }
  }
  return names;
}

// Extract balanced `Display` and `Debug` formatter bodies.
function displayDebugFmtBodies(source) {
  const bodies = [];
  const implRe = /impl(?:<[^>]*>)?\s+(?:std::)?fmt::(Display|Debug)\s+for\s+([\w:]+)/g;
  let impl;
  while ((impl = implRe.exec(source))) {
    const fnIndex = source.indexOf("fn fmt", impl.index);
    if (fnIndex === -1) continue;
    const open = source.indexOf("{", fnIndex);
    if (open === -1) continue;
    let depth = 0;
    for (let i = open; i < source.length; i += 1) {
      const ch = source[i];
      if (ch === "{") depth += 1;
      else if (ch === "}") {
        depth -= 1;
        if (depth === 0) {
          bodies.push({ trait: impl[1], type: impl[2], body: source.slice(open, i + 1) });
          break;
        }
      }
    }
  }
  return bodies;
}

export function displayImplLogReentrancyFailures(read, listFiles, extraRoots = []) {
  const failures = [];
  const files = [...RUST_SRC_DIRS, ...extraRoots].flatMap((dir) =>
    listFiles(dir, (name) => name.endsWith(".rs")),
  );
  for (const file of files) {
    const source = read(file);
    if (!source.includes("#[tracing::instrument") || !/fmt::(?:Display|Debug)\s+for/.test(source)) {
      continue;
    }
    const instrumented = instrumentedFnNames(source);
    if (instrumented.size === 0) continue;
    for (const { trait: traitName, type, body } of displayDebugFmtBodies(source)) {
      for (const name of instrumented) {
        if (new RegExp(`\\b${name}\\s*\\(`).test(body)) {
          failures.push(
            `${file}: \`${type}\` ${traitName} fmt calls #[tracing::instrument] fn \`${name}\`. ` +
              "Display/Debug fmt impls run inside the log writer lock (tracing fields format " +
              "lazily under fern's mutex), so emitting a span there re-enters the same " +
              `non-reentrant mutex and deadlocks. Remove the instrument from \`${name}\` and keep ` +
              "Display/Debug log-free.",
          );
        }
      }
    }
  }
  return failures;
}
