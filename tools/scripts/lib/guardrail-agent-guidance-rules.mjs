import { posix as path } from "node:path";

const AGENT_GUIDANCE_SURFACES = [
  ".",
  ".github",
  "docs",
  "packaging/npm",
  "tools/scripts",
  "apps/desktop/src-tauri",
  "apps/desktop/src-tauri/crates/cli",
  "apps/desktop/src-tauri/crates/engine-host",
  "apps/desktop/src-tauri/crates/protocol",
  "apps/desktop/src-tauri/src",
  "apps/desktop/src-tauri/src/cli",
  "apps/desktop/src-tauri/src/core",
  "apps/desktop/src-tauri/src/db",
];
const MAX_PROSE_LINE_LENGTH = 160;

function longProseLines(file, source) {
  const failures = [];
  let inFence = false;
  for (const [index, line] of source.split("\n").entries()) {
    if (line.trimStart().startsWith("```")) {
      inFence = !inFence;
      continue;
    }
    if (inFence || line.trimStart().startsWith("|")) continue;
    if (line.length > MAX_PROSE_LINE_LENGTH) failures.push(`${file}:${index + 1}`);
  }
  return failures;
}

export function agentGuidanceFailures(read, exists, listFiles) {
  const failures = [];

  const missingGuides = AGENT_GUIDANCE_SURFACES.flatMap((dir) =>
    ["AGENTS.md", "CLAUDE.md"].map((name) => path.join(dir, name)).filter((file) => !exists(file)),
  );
  if (missingGuides.length > 0) {
    failures.push(
      `Every app surface needs an AGENTS.md and a CLAUDE.md pointer so directory-local rules travel with the code: ${missingGuides.join(", ")}`,
    );
  }

  const guideFiles = listFiles(".", (file) => path.basename(file) === "AGENTS.md");
  const imports = new Set(listFiles(".", (file) => path.basename(file) === "CLAUDE.md"));
  for (const guide of guideFiles) {
    const claude = path.join(path.dirname(guide), "CLAUDE.md");
    if (!imports.has(claude) && !missingGuides.includes(claude)) {
      failures.push(`${guide} must have a sibling CLAUDE.md`);
    }
  }
  for (const file of imports) {
    if (read(file) !== "@AGENTS.md\n") {
      failures.push(`${file} must be exactly @AGENTS.md followed by a newline`);
    }
  }

  const guidanceFiles = ["AGENTS.md", ...listFiles("apps", (file) => file.endsWith("/AGENTS.md"))]
    .filter(exists)
    .flatMap((file) => longProseLines(file, read(file)));
  if (guidanceFiles.length > 0) {
    failures.push(
      `AGENTS.md prose lines must stay within ${MAX_PROSE_LINE_LENGTH} characters; wrap guidance instead of creating narrative walls: ${guidanceFiles.join(", ")}`,
    );
  }

  return failures;
}
