const MARKER = "allow-lazy-plural";

// Extract unescaped double-quoted spans from one source line.
function stringLiteralSpans(line) {
  const spans = [];
  let inString = false;
  let current = "";
  for (let i = 0; i < line.length; i += 1) {
    const ch = line[i];
    if (ch === "\\" && inString) {
      current += ch + (line[i + 1] ?? "");
      i += 1;
      continue;
    }
    if (ch === '"') {
      if (inString) {
        spans.push(current);
        current = "";
      }
      inString = !inString;
      continue;
    }
    if (inString) current += ch;
  }
  return spans;
}

export function lazyPluralFailures(read, exists, listFiles, roots = []) {
  const failures = [];
  for (const dir of roots) {
    if (!exists(dir)) continue;
    for (const file of listFiles(dir, (f) => f.endsWith(".rs"))) {
      const lines = read(file).split("\n");
      for (let i = 0; i < lines.length; i += 1) {
        const line = lines[i];
        if (!line.includes("(s)") || line.includes(MARKER)) continue;
        if (stringLiteralSpans(line).some((span) => span.includes("(s)"))) {
          failures.push(
            `${file}:${i + 1} - lazy plural "(s)" in emitted copy; pluralize properly (conditional word form or plural_suffix helper). Line: ${line.trim()}`,
          );
        }
      }
    }
  }
  return failures;
}
