const REQUIRED_FILES = [
  ".env.example",
  ".gitattributes",
  ".github/CODEOWNERS",
  ".github/ISSUE_TEMPLATE/bug_report.yml",
  ".github/ISSUE_TEMPLATE/config.yml",
  ".github/ISSUE_TEMPLATE/feature_request.yml",
  ".github/pull_request_template.md",
  ".gitignore",
  ".gitleaks.toml",
  "CHANGELOG.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "install.sh",
  "LICENSE",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "SUPPORT.md",
  "THIRD_PARTY_NOTICES",
  "THIRD_PARTY_DEPENDENCIES.json",
  "THIRD_PARTY_LICENSES.txt",
  "tools/scripts/check-publication-hygiene.mjs",
  "tools/scripts/check-publication-hygiene.test.mjs",
  "tools/scripts/check-publication-history.mjs",
  "tools/scripts/check-publication-history.test.mjs",
  "tools/scripts/prepare-public-history.mjs",
  "tools/scripts/prepare-public-history.test.mjs",
  "tools/scripts/lib/publication-hygiene-rules.mjs",
  "tools/scripts/lib/publication-history-rules.mjs",
];

const ALLOWED_ROOT_FILES = new Set([
  ".env.example",
  ".gitattributes",
  ".gitignore",
  ".gitleaks.toml",
  ".nvmrc",
  ".prettierignore",
  ".prettierrc.json",
  "AGENTS.md",
  "CHANGELOG.md",
  "CLAUDE.md",
  "CODE_OF_CONDUCT.md",
  "CONTRIBUTING.md",
  "GOVERNANCE.md",
  "LICENSE",
  "NOTICE",
  "README.md",
  "SECURITY.md",
  "SUPPORT.md",
  "THIRD_PARTY_DEPENDENCIES.json",
  "THIRD_PARTY_LICENSES.txt",
  "THIRD_PARTY_NOTICES",
  "eslint.config.js",
  "install.sh",
  "knip.config.ts",
  "lefthook.yml",
  "package.json",
  "pnpm-lock.yaml",
  "pnpm-workspace.yaml",
  "product-facts.json",
  "renovate.json",
  "vitest.config.mjs",
]);

const ALLOWED_ROOT_DIRECTORIES = new Set([".github", "apps", "docs", "tools"]);

// Session directories are forbidden at any repository depth.
const FORBIDDEN_TOOL_DIRECTORIES = new Set([
  ".agents",
  ".artifacts",
  ".bg-shell",
  ".claude",
  ".codex",
  ".cursor",
  ".design-sync",
  ".ds-sync",
  ".gemini",
  ".gsd",
  ".impeccable",
  ".playwright-cli",
  ".playwright-mcp",
  ".superpowers",
  "ds-bundle",
]);

// Root-only working directories; prefix anchoring avoids matching ordinary
// source path segments with the same names.
const FORBIDDEN_PREFIXES = [
  "artifacts/",
  "design/",
  "docs/audit/",
  "docs/qa/acceptance-reviews/",
  "docs/superpowers/",
  "planning/",
];

const FORBIDDEN_SEGMENTS = new Set([
  ".cache",
  ".pytest_cache",
  "__pycache__",
  "coverage",
  "dist",
  "node_modules",
  "playwright-report",
  "target",
  "test-results",
]);

const FORBIDDEN_SUFFIXES = [
  ".bak",
  ".db",
  ".db-shm",
  ".db-wal",
  ".diff",
  ".log",
  ".orig",
  ".patch",
  ".pid",
  ".rej",
  ".sqlite",
  ".sqlite3",
  ".swo",
  ".swp",
  ".temp",
  ".tmp",
];

// Release tag verification compares protected trust with this reviewed mirror.
const FORBIDDEN_EXACT_FILES = new Set([
  ".gitleaksignore",
  ".github/hooks/impeccable.json",
  "apps/mcp-server/LICENSE",
  "sitecmd-positioning-convo.txt",
]);

const OS_METADATA_NAMES = new Set([".ds_store", "desktop.ini", "thumbs.db"]);
const MAX_PATH_LENGTH = 180;
const MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024;
const MACHINE_PATH_RE = /(?:\/Users\/[^/\s]+\/|\/home\/[^/\s]+\/|[A-Za-z]:\\Users\\[^\\\s]+\\)/;

// Match anchored machine homes without flagging ordinary `pages/home` paths.
const SOURCE_TEXT_EXTENSIONS = new Set([
  ".astro",
  ".css",
  ".js",
  ".jsonc",
  ".mjs",
  ".py",
  ".rs",
  ".sh",
  ".sql",
  ".swift",
  ".toml",
  ".ts",
  ".tsx",
  ".yaml",
  ".yml",
]);
// Case-sensitive on purpose. macOS spells its home root `/Users/` and Windows
// `C:\Users\`, both capitalized; a lowercase `/users/` is a URL path segment,
// and matching it folded reported `api.patch("/users/profile")` as the home
// directory of an account named "profile".
const HOME_DIRECTORY_RE =
  /(?:^|[\s"'`(=:,[])(?:\/Users\/|\/home\/|%2FUsers%2F|[A-Za-z]:\\Users\\)([A-Za-z0-9._-]+)/g;
const PLACEHOLDER_HOME_NAMES = new Set([
  // Fixed guest service accounts are not personal login names.
  "benchadmin",
  "ci",
  "dev",
  "example",
  "me",
  "runner",
  "sitecmd",
  "test",
  "tester",
  "user",
  "you",
]);

function isSourceText(path) {
  const dot = path.lastIndexOf(".");
  return dot === -1 ? false : SOURCE_TEXT_EXTENSIONS.has(path.slice(dot).toLowerCase());
}

/** Home directories in `source` that name a real account rather than a fixture. */
function realHomeDirectoryNames(source) {
  const found = new Set();
  for (const [, name] of source.matchAll(HOME_DIRECTORY_RE)) {
    if (!PLACEHOLDER_HOME_NAMES.has(name.toLowerCase())) found.add(name);
  }
  return [...found].sort();
}

function isPublicText(path) {
  if (
    /^(?:README|CONTRIBUTING|SECURITY|SUPPORT|GOVERNANCE|CHANGELOG|CODE_OF_CONDUCT)\.md$/.test(path)
  ) {
    return true;
  }
  if (path.startsWith("docs/") || path.startsWith(".github/")) return true;
  if (/(?:^|\/)(?:AGENTS|CLAUDE|PRODUCT|README)\.md$/.test(path)) return true;
  return false;
}

function rootEntry(path) {
  const slash = path.indexOf("/");
  return slash === -1 ? path : path.slice(0, slash);
}

function contentIncludes(read, path, expected) {
  try {
    return read(path).includes(expected);
  } catch {
    return false;
  }
}

export function publicationHygieneFailures(files, read) {
  const failures = [];
  const paths = files.map((file) => file.path.replaceAll("\\", "/")).sort();
  const pathSet = new Set(paths);

  for (const required of REQUIRED_FILES) {
    if (!pathSet.has(required)) {
      failures.push(`missing required public-repository file: ${required}`);
    }
  }

  for (const path of paths) {
    const lowerPath = path.toLowerCase();
    const segments = lowerPath.split("/");
    const basename = segments.at(-1);

    if (FORBIDDEN_EXACT_FILES.has(path)) {
      failures.push(`tracked publication residue is forbidden: ${path}`);
    }
    if (
      FORBIDDEN_PREFIXES.some((prefix) => lowerPath.startsWith(prefix)) ||
      segments.some((segment) => FORBIDDEN_TOOL_DIRECTORIES.has(segment))
    ) {
      failures.push(`generated, private, or session-scoped path is forbidden: ${path}`);
    }
    if (segments.some((segment) => FORBIDDEN_SEGMENTS.has(segment))) {
      failures.push(`generated directory is forbidden in the public snapshot: ${path}`);
    }
    if (OS_METADATA_NAMES.has(basename)) {
      failures.push(`operating-system metadata is forbidden: ${path}`);
    }
    if (FORBIDDEN_SUFFIXES.some((suffix) => lowerPath.endsWith(suffix))) {
      failures.push(`temporary, database, or patch artifact is forbidden: ${path}`);
    }
    if (path.length > MAX_PATH_LENGTH) {
      failures.push(`path exceeds ${MAX_PATH_LENGTH} characters: ${path}`);
    }

    const file = files.find((candidate) => candidate.path.replaceAll("\\", "/") === path);
    if (file && file.size > MAX_TRACKED_FILE_BYTES) {
      failures.push(
        `file exceeds the ${MAX_TRACKED_FILE_BYTES / 1024 / 1024} MiB publication limit: ${path}`,
      );
    }
    if (file && file.size === 0 && basename !== ".gitkeep") {
      failures.push(`empty tracked file is forbidden unless it is .gitkeep: ${path}`);
    }

    const root = rootEntry(path);
    if (
      !path.includes("/") &&
      !ALLOWED_ROOT_FILES.has(path) &&
      !ALLOWED_ROOT_DIRECTORIES.has(root)
    ) {
      failures.push(`unexpected file at repository root: ${path}`);
    }

    if (isPublicText(path)) {
      let source = "";
      try {
        source = read(path);
      } catch {
        failures.push(`unable to read public text file: ${path}`);
      }
      if (MACHINE_PATH_RE.test(source)) {
        failures.push(`machine-specific absolute path appears in public text: ${path}`);
      }
    } else if (isSourceText(path)) {
      let source = "";
      try {
        source = read(path);
      } catch {
        failures.push(`unable to read source file: ${path}`);
      }
      const realHomes = realHomeDirectoryNames(source);
      if (realHomes.length > 0) {
        failures.push(
          `real home directory appears in source: ${path} (${realHomes.join(", ")}). ` +
            `Use a placeholder such as /Users/dev/ in fixtures.`,
        );
      }
    }
  }

  const caseFolded = new Map();
  for (const path of paths) {
    const key = path.toLowerCase();
    const existing = caseFolded.get(key);
    if (existing && existing !== path) {
      failures.push(`case-insensitive path collision: ${existing} and ${path}`);
    } else {
      caseFolded.set(key, path);
    }
  }

  const requiredContent = [
    {
      path: "package.json",
      expected: '"license": "Apache-2.0"',
      label: "open-source package metadata",
    },
    {
      path: "apps/mcp-server/package.json",
      expected: '"license": "Apache-2.0"',
      label: "open-source package metadata",
    },
    {
      path: "apps/desktop/src-tauri/Cargo.toml",
      expected: 'license = "Apache-2.0"',
      label: "open-source package metadata",
    },
    {
      path: ".github/CODEOWNERS",
      expected: "@brambleworks",
      label: "repository ownership",
    },
    {
      path: "renovate.json",
      expected: '"automergeType": "pr"',
      label: "dependency automation",
    },
    {
      path: "renovate.json",
      expected: '"platformCommit": "enabled"',
      label: "dependency automation",
    },
  ];
  for (const { path, expected, label } of requiredContent) {
    if (pathSet.has(path) && !contentIncludes(read, path, expected)) {
      failures.push(`${label} must contain ${expected}: ${path}`);
    }
  }
  if (
    pathSet.has("renovate.json") &&
    contentIncludes(read, "renovate.json", '"automergeType": "branch"')
  ) {
    failures.push(
      'dependency automation must not bypass pull requests with "automergeType": "branch": renovate.json',
    );
  }
  if (pathSet.has("renovate.json")) {
    try {
      const renovate = JSON.parse(read("renovate.json"));
      const allowedAutomaticUpdateTypes = new Set(["minor", "patch", "pin", "digest"]);
      if (renovate.automerge === true) {
        failures.push(
          "Renovate auto-merge must be scoped to explicit package rules, not enabled globally.",
        );
      }
      for (const rule of renovate.packageRules ?? []) {
        if (rule.automerge !== true) continue;
        const updateTypes = rule.matchUpdateTypes;
        if (
          !Array.isArray(updateTypes) ||
          updateTypes.length === 0 ||
          updateTypes.some((type) => !allowedAutomaticUpdateTypes.has(type))
        ) {
          failures.push(
            `Renovate auto-merge rule "${rule.description ?? rule.groupName ?? "unnamed"}" must explicitly limit matchUpdateTypes to minor, patch, pin, or digest updates.`,
          );
        }
      }
      const preOneManualReview = (renovate.packageRules ?? []).some(
        (rule) => rule.matchCurrentVersion === "/^0\\./" && rule.automerge === false,
      );
      if (!preOneManualReview) {
        failures.push(
          "Renovate must disable auto-merge for pre-1.0 packages with a /^0\\./ matchCurrentVersion rule.",
        );
      }
      if (renovate.vulnerabilityAlerts?.automerge !== false) {
        failures.push("Renovate vulnerability-alert pull requests must require manual review.");
      }
    } catch (error) {
      failures.push(`renovate.json is not valid JSON: ${error.message}`);
    }
  }

  if (pathSet.has("THIRD_PARTY_NOTICES")) {
    const notices = read("THIRD_PARTY_NOTICES");
    const releaseWorkflows = paths.filter(
      (path) => path.startsWith(".github/workflows/") && /release/i.test(path),
    );
    if (
      /\bSBOM\b|software bill of materials/i.test(notices) &&
      !releaseWorkflows.some((path) => /\bSBOM\b|software bill of materials/i.test(read(path)))
    ) {
      failures.push(
        "THIRD_PARTY_NOTICES claims a release SBOM, but no release workflow generates one.",
      );
    }
    for (const match of notices.matchAll(/^Vendored file:\s+(.+)$/gm)) {
      if (!pathSet.has(match[1].trim())) {
        failures.push(`THIRD_PARTY_NOTICES lists missing vendored material: ${match[1].trim()}`);
      }
    }
  }

  return [...new Set(failures)].sort();
}
