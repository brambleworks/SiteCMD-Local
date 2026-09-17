const MATRIX = "docs/engineering/connected-service/maintained-surfaces.md";
const PUBLICATION_CHECKLIST = "docs/operations/publication-checklist.md";
const README = "README.md";
const CONTRIBUTING = "CONTRIBUTING.md";
const SECURITY = "SECURITY.md";
const CONNECTED_SPEC_DIRECTORY = "docs/engineering/connected-service";
const SECURITY_CONTACT_KEY = ".github/security-contact-key.asc";

const RETIRED_LOCAL_CONTRACT =
  /Tier::has_feature|Feature::IssueRichDetail|detailsUnlocked|locked on this tier|unlock details|unlock this finding|Code Scan (?:requires (?:Core or Pro|a paid license)|is a paid Core feature)|paid features are off|Cached features are still active|features will downgrade to Free/i;

const ROOT_PRODUCT_DOCS = [
  "README.md",
  "CONTRIBUTING.md",
  "SECURITY.md",
  "SUPPORT.md",
  "GOVERNANCE.md",
  "CHANGELOG.md",
  "AGENTS.md",
];

const CLAIM_MARKERS =
  /Free tier|Core tier|Pro tier|Plus tier|Free\/Core|Free\/paid|\$\d+\/(?:month|year)|never leaves? (?:your |the user's |the )?machine|never see your code|Intelligence Pack|stays? on the user's machine/i;

const PRIVATE_RECORD_LINK =
  /\]\([^)]*(?:publication-decision|paid-intelligence-rfc|commercial-terms-spec|connected-service-rfc)\.md[^)]*\)/;

const UNQUALIFIED_NETWORK_ENUMERATION =
  /\b(?:every|all)\s+outbound\s+(?:calls?|requests?)\b[^.!?]{0,80}\bby name\b/i;

// A sentence that denies complete enumeration states the limitation the rule
// exists to protect, so only affirmative claims fail.
const ENUMERATION_DENIAL = /\b(?:no|not|never|cannot|can't)\b/i;

function claimsCompleteNetworkEnumeration(markdown) {
  return markdown
    .replace(/\s+/g, " ")
    .split(/(?<=[.!?])\s+/)
    .some((sentence) => {
      const match = UNQUALIFIED_NETWORK_ENUMERATION.exec(sentence);
      return match != null && !ENUMERATION_DENIAL.test(sentence.slice(0, match.index));
    });
}

const APP_REFERENCE = /(?<![\w.-])apps\/([\w.-]+)/g;

function pathTokens(markdown) {
  const tokens = new Set();
  for (const match of markdown.matchAll(/`([\w.@/-]+)`/g)) {
    const token = match[1].replace(/\*$/, "");
    if (token.includes("/") || token.endsWith(".md")) tokens.add(token);
  }
  return [...tokens];
}

function presentInTree(token, exists, listFiles) {
  const clean = token.replace(/\/$/, "");
  if (exists(clean)) return true;
  try {
    return listFiles(clean, () => true).length > 0;
  } catch {
    return false;
  }
}

function workspacePackageNames(read, listFiles) {
  const names = new Set(["sitecmd-workspace"]);
  for (const manifest of listFiles("apps", (file) => /^apps\/[^/]+\/package\.json$/.test(file))) {
    try {
      const name = JSON.parse(read(manifest)).name;
      if (name) names.add(name);
    } catch {
      // Invalid manifests are reported by another guardrail.
    }
  }
  return names;
}

function appDirectories(listFiles) {
  const apps = new Set();
  for (const manifest of listFiles("apps", (file) => /^apps\/[^/]+\/package\.json$/.test(file))) {
    apps.add(manifest.split("/")[1]);
  }
  return apps;
}

export function publicationRecordFailures(read, exists, listFiles) {
  const failures = [];

  if (exists(README) && claimsCompleteNetworkEnumeration(read(README))) {
    failures.push(
      `${README} must describe fixed network hosts by name and dynamic destinations by class; scan targets, subresources, integrations, providers, and webhooks cannot be enumerated in advance.`,
    );
  }

  for (const file of listFiles(CONNECTED_SPEC_DIRECTORY, (path) => path.endsWith("-spec.md"))) {
    const source = read(file);
    const firstSection = source.split("\n").findIndex((line) => line.startsWith("## "));
    if (firstSection === -1 || firstSection > 60) {
      failures.push(
        `${file} must reach its first normative section within 60 lines; keep revision transcripts in Git.`,
      );
    }
    if (
      /\bAmended a [\w-]+ time\b|\bcross-spec review round\b|\b(?:earlier|previous) (?:draft|revision|wording)\b|\b(?:was|is|has been) amended\b|\bcontract correction surfaced\b|\bFor reviewers\b/i.test(
        source,
      )
    ) {
      failures.push(`${file} contains a retained review transcript; keep revision history in Git.`);
    }
  }

  // Retired paid-boundary phrases may remain only in historical specs and tests.
  const retiredContractSurfaces = [
    ...[
      README,
      CONTRIBUTING,
      SECURITY,
      "apps/desktop/PRODUCT.md",
      "docs/engineering/tauri.md",
    ].filter(exists),
    ...listFiles(
      "apps/desktop/src",
      (file) =>
        /\.(?:ts|tsx|css)$/.test(file) && !/\.test\./.test(file) && !file.includes("/generated/"),
    ),
    ...listFiles(
      "apps/desktop/src-tauri/src",
      (file) => file.endsWith(".rs") && !file.endsWith("_tests.rs") && !file.includes("/tests/"),
    ),
  ];
  for (const file of retiredContractSurfaces) {
    if (RETIRED_LOCAL_CONTRACT.test(read(file))) {
      failures.push(
        `${file} repeats the retired client-side paid-feature contract; the complete local workbench is free and hosted entitlement is server-enforced.`,
      );
    }
  }

  const linkSweep = [
    ...ROOT_PRODUCT_DOCS.filter(exists),
    ...listFiles("docs", (file) => file.endsWith(".md")),
    ...listFiles("apps", (file) => /\/(PRODUCT|AGENTS)\.md$/.test(file)),
  ];
  for (const file of linkSweep) {
    if (PRIVATE_RECORD_LINK.test(read(file))) {
      failures.push(
        `${file} links a business strategy record that lives in the private repository; a public reader lands on a 404. Name it in plain text instead.`,
      );
    }
  }

  if (!exists(MATRIX)) {
    failures.push(
      `The maintained-surface matrix must exist at ${MATRIX}; phrase bans catch verbatim drift, while the matrix catches semantic drift.`,
    );
    return failures;
  }
  if (!exists(PUBLICATION_CHECKLIST)) {
    failures.push(`The in-place public cutover checklist must exist at ${PUBLICATION_CHECKLIST}.`);
  }
  const matrix = read(MATRIX);
  if (
    /Founder acceptance:\s*Pending|Pending explicit review|replace this line with the reviewer/i.test(
      matrix,
    )
  ) {
    failures.push(
      `${MATRIX} contains a live founder-acceptance status; keep dated release decisions in the private release record.`,
    );
  }
  const localSection = matrix.split(/^## SiteCMD-Web/m)[0];
  for (const token of pathTokens(localSection)) {
    if (!presentInTree(token, exists, listFiles)) {
      failures.push(
        `${MATRIX} lists \`${token}\` as a surface in this repository, but nothing is there. Remove the row or fix the path.`,
      );
    }
  }

  const claimSurfaces = [
    ...ROOT_PRODUCT_DOCS.filter(exists),
    ...listFiles("apps", (file) => /\/(PRODUCT|AGENTS)\.md$/.test(file)),
    ...listFiles("docs", (file) => file.startsWith("docs/product/") && file.endsWith(".md")),
  ];
  for (const file of claimSurfaces) {
    // Match promises across Markdown line wrapping.
    if (!CLAIM_MARKERS.test(read(file).replace(/\s+/g, " "))) continue;
    const basename = file.split("/").pop();
    if (!matrix.includes(file) && !matrix.includes(basename)) {
      failures.push(
        `${file} asserts a boundary, pricing, or privacy claim but has no row in ${MATRIX}.`,
      );
    }
  }

  const apps = appDirectories(listFiles);
  for (const file of [README, CONTRIBUTING].filter(exists)) {
    const contents = read(file);
    for (const reference of contents.matchAll(APP_REFERENCE)) {
      if (!apps.has(reference[1])) {
        failures.push(
          `${file} maps \`apps/${reference[1]}/\`, which is not a workspace in this repository.`,
        );
      }
    }
    for (const app of apps) {
      if (!contents.includes(app)) {
        failures.push(`${file} must name the \`${app}\` workspace in its repo layout.`);
      }
    }
  }

  for (const script of listFiles("tools", (file) => file.endsWith(".sh"))) {
    for (const reference of read(script).matchAll(APP_REFERENCE)) {
      if (!apps.has(reference[1])) {
        failures.push(
          `${script} points at \`apps/${reference[1]}/\`, which is not a workspace in this repository.`,
        );
      }
    }
  }

  // pnpm exits successfully when a filter selects no workspace.
  const packages = workspacePackageNames(read, listFiles);
  const filterSources = [
    ...ROOT_PRODUCT_DOCS.filter(exists),
    ...listFiles("docs", (file) => file.endsWith(".md")),
    ...listFiles(
      "tools",
      (file) =>
        (file.endsWith(".sh") || file.endsWith(".mjs") || file.endsWith(".md")) &&
        !file.endsWith(".test.mjs"),
    ),
  ];
  for (const file of filterSources) {
    // Ignore example filters inside guardrail comments.
    const source = file.endsWith(".mjs")
      ? read(file)
          .split("\n")
          .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
          .join("\n")
      : read(file);
    for (const use of source.matchAll(/--filter[= ]+"?([@\w./-]+)"?/g)) {
      const name = use[1];
      if (name.startsWith("$") || name.startsWith("-")) continue;
      if (!packages.has(name)) {
        failures.push(
          `${file} runs \`--filter ${name}\`, which is not a workspace package. pnpm exits zero on an empty selection, so this fails silently.`,
        );
      }
    }
  }

  if (exists(SECURITY)) {
    const security = read(SECURITY);
    if (!/connected service/i.test(security)) {
      failures.push(
        `${SECURITY} must state that the connected service is in scope: its API, hosted scanner, and delivery paths are where a report has nowhere else to go.`,
      );
    }
    for (const page of ["https://sitecmd.com/trust", "https://sitecmd.com/privacy"]) {
      if (!security.includes(page)) {
        failures.push(`${SECURITY} must point at ${page}, where the boundaries it protects live.`);
      }
    }
    // The advisories URL must be a markdown link target, parentheses and all:
    // bare substring containment would accept the URL embedded inside another
    // host's URL (CodeQL js/incomplete-url-substring-sanitization), and a
    // mention that is not a link does not give a reporter anything to click.
    if (
      !/\(https:\/\/github\.com\/brambleworks\/SiteCMD-Local\/security\/advisories\/new\)/.test(
        security,
      )
    ) {
      failures.push(
        `${SECURITY} must link GitHub private vulnerability reporting as the first channel; protection:check:live proves it is enabled.`,
      );
    }
    if (
      !security.includes("security@sitecmd.com") ||
      !security.includes(`(${SECURITY_CONTACT_KEY})`) ||
      !exists(SECURITY_CONTACT_KEY)
    ) {
      failures.push(
        `${SECURITY} must name security@sitecmd.com and the committed OpenPGP key at ${SECURITY_CONTACT_KEY} for reports that cannot use GitHub.`,
      );
    }
    const advisories = security.indexOf("/security/advisories/new");
    const mailbox = security.indexOf("security@sitecmd.com");
    if (advisories !== -1 && mailbox !== -1 && mailbox < advisories) {
      failures.push(
        `${SECURITY} must list GitHub private vulnerability reporting before the email channel; the report that can stay on GitHub should.`,
      );
    }
    if (exists(SECURITY_CONTACT_KEY)) {
      const key = read(SECURITY_CONTACT_KEY);
      if (
        !key.startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----") ||
        !key.includes("-----END PGP PUBLIC KEY BLOCK-----")
      ) {
        failures.push(
          `${SECURITY_CONTACT_KEY} must be an armored OpenPGP public key block; a truncated or malformed key prevents encrypted reporting.`,
        );
      }
    }
    if (/when (?:it is )?available/i.test(security)) {
      failures.push(
        `${SECURITY} must not hedge about private vulnerability reporting; it is enabled, and a reporter who reads "when available" assumes it is not.`,
      );
    }
  }

  return failures;
}
