const SCANNED_DIRS = ["apps/desktop/src-tauri/src/core"];

export function inlineDurationFailures(read, exists, listFiles, extraRoots = []) {
  const failures = [];
  const inlineDurationViolations = [];
  const literalRegex = /Duration::from_secs\s*\(\s*\d/g;
  for (const dir of [...SCANNED_DIRS, ...extraRoots]) {
    if (!exists(dir)) continue;
    const files = listFiles(dir, (file) => file.endsWith(".rs"));
    for (const file of files) {
      const source = read(file);
      // Dedicated and inline test modules may use scenario-specific durations.
      if (/(\.test|\.spec)\.rs$/.test(file)) continue;
      if (/(?:^|\/)tests\.rs$/.test(file)) continue;
      if (/_tests\.rs$/.test(file)) continue;
      const lines = source.split(/\r\n|\r|\n/);
      let inTestBlock = false;
      let testDepth = 0;
      for (let lineIndex = 0; lineIndex < lines.length; lineIndex += 1) {
        const rawLine = lines[lineIndex];
        const lineText = rawLine ?? "";
        if (/#\[cfg\(test\)\]/.test(lineText)) {
          inTestBlock = true;
          testDepth = 0;
          continue;
        }
        if (inTestBlock) {
          for (const ch of lineText) {
            if (ch === "{") testDepth += 1;
            else if (ch === "}") {
              testDepth -= 1;
              if (testDepth <= 0) {
                inTestBlock = false;
                testDepth = 0;
                break;
              }
            }
          }
          continue;
        }
        if (lineText.includes("// allow-inline-duration")) continue;
        literalRegex.lastIndex = 0;
        if (literalRegex.test(lineText)) {
          // Allow a nearby marker directly above the literal.
          let approved = false;
          for (let prev = lineIndex - 1; prev >= 0 && prev >= lineIndex - 4; prev -= 1) {
            const prevLine = (lines[prev] ?? "").trim();
            if (prevLine === "") continue;
            if (prevLine.includes("// allow-inline-duration")) {
              approved = true;
              break;
            }
            if (!prevLine.startsWith("//") && !prevLine.startsWith("/*")) {
              break;
            }
          }
          if (!approved) {
            inlineDurationViolations.push(`${file}:${lineIndex + 1}`);
          }
        }
      }
    }
  }
  if (inlineDurationViolations.length > 0) {
    failures.push(
      `Move bare Duration::from_secs(N) literals into apps/desktop/src-tauri/src/constants.rs (or annotate with // allow-inline-duration when a real exception applies): ${inlineDurationViolations.join(", ")}`,
    );
  }
  return failures;
}
