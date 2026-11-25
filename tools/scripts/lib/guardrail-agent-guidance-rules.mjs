const AGENT_GUIDANCE_SURFACES = ["apps/desktop/src-tauri"];
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
    ["AGENTS.md", "CLAUDE.md"].map((name) => `${dir}/${name}`).filter((file) => !exists(file)),
  );
  if (missingGuides.length > 0) {
    failures.push(
      `Every app surface needs an AGENTS.md and a CLAUDE.md pointer so directory-local rules travel with the code: ${missingGuides.join(", ")}`,
    );
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
