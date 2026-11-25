export function documentationSafetyFailures(read, exists, listFiles) {
  const failures = [];
  const pushIf = (condition, message) => {
    if (condition) failures.push(message);
  };

  const guidanceFiles = [
    "CLAUDE.md",
    "AGENTS.md",
    ...listFiles("apps", (file) => /(^|\/)(CLAUDE|AGENTS|README)\.md$/i.test(file)),
  ].filter(exists);
  const docFiles = [
    "README.md",
    ...listFiles("docs", (file) => file.endsWith(".md")),
    ...guidanceFiles,
  ];
  const localAbsoluteMarkdownLinks = docFiles.filter((file) =>
    /\]\(\/Users\/[^)]+\)/.test(read(file)),
  );
  pushIf(
    localAbsoluteMarkdownLinks.length > 0,
    `Documentation must not use machine-specific absolute Markdown links: ${localAbsoluteMarkdownLinks.join(", ")}`,
  );

  const staleAdminKeyGuidanceFiles = guidanceFiles.filter((file) =>
    /\?key=<ADMIN_KEY>|auth via `\?key=<ADMIN_KEY>`/.test(read(file)),
  );
  pushIf(
    staleAdminKeyGuidanceFiles.length > 0,
    `Repo guidance must not document query-string admin keys: ${staleAdminKeyGuidanceFiles.join(", ")}`,
  );

  const staleTypecheckGuidanceFiles = guidanceFiles.filter((file) =>
    /No [`"']?(lint|typecheck)[`"']? or [`"']?(lint|typecheck)[`"']? scripts exist|No [`"']?typecheck[`"']? scripts exist/.test(
      read(file),
    ),
  );
  pushIf(
    staleTypecheckGuidanceFiles.length > 0,
    `Repo guidance must not claim missing typecheck scripts after quality gates exist: ${staleTypecheckGuidanceFiles.join(", ")}`,
  );

  const staleArchitectureGuidanceFiles = guidanceFiles.filter((file) =>
    /core\/guardrails\.rs|AppGuardrailsReport|gate lives in the frontend display layer|New commands must[^.\n]+capabilities\/default\.json|Add to [`"']?capabilities\/default\.json|credentials fall back to SQLite/.test(
      read(file),
    ),
  );
  pushIf(
    staleArchitectureGuidanceFiles.length > 0,
    `Repo guidance must not describe stale Code Scan or Tauri capability architecture: ${staleArchitectureGuidanceFiles.join(", ")}`,
  );

  return failures;
}
