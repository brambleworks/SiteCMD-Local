const PRODUCT_DOCS = "docs/product";
const DOCS_INDEX = "docs/README.md";
const CONTRIBUTING = "CONTRIBUTING.md";
const CONNECTED_SPECS = "docs/engineering/connected-service";
const LOCALHOST_FIXTURES = "apps/desktop/src-tauri/src/core/localhost.rs";
const README = "README.md";
const PRODUCT_FACTS = "product-facts.json";

// The README restates generated check counts. Drift turns a fact a reader can
// verify against the registries into a marketing claim they cannot.
const README_COUNT_ROWS = [
  ["Web Scan", "web"],
  ["Code Scan", "codeScan"],
  ["Accessibility", "axe"],
  ["Polish", "polish"],
];

function checkCountFailures(read, exists) {
  if (!exists(README) || !exists(PRODUCT_FACTS)) return [];
  const readme = read(README);
  const counts = JSON.parse(read(PRODUCT_FACTS)).checkCounts;
  const failures = [];
  for (const [label, key] of README_COUNT_ROWS) {
    const row = new RegExp(`^\\|\\s*${label}\\s*\\|\\s*(\\d+)\\s*\\|`, "m").exec(readme);
    if (!row) {
      failures.push(
        `${README} must keep a "${label}" row in its check-count table; ${PRODUCT_FACTS} publishes ${counts[key]}.`,
      );
    } else if (Number(row[1]) !== counts[key]) {
      failures.push(
        `${README} says ${label} runs ${row[1]} checks and ${PRODUCT_FACTS} says ${counts[key]}. Run pnpm facts:generate, then update the table.`,
      );
    }
  }
  const ecosystems = /across (\d+) package ecosystems/.exec(readme);
  if (!ecosystems || Number(ecosystems[1]) !== counts.dependencyEcosystems) {
    failures.push(
      `${README} must say dependency findings resolve across ${counts.dependencyEcosystems} package ecosystems, the count ${PRODUCT_FACTS} publishes.`,
    );
  }
  return failures;
}

// Product-intent phrasing belongs in docs/qa, where reviewers read it.
const INTENT_PHRASES =
  /SiteCMD should|treat that as product feedback|should make (?:that|the) [a-z-]+ (?:step )?obvious/i;
// Plain-text names of private records are allowed; deferring a rule to one is not.
const PRIVATE_RECORD_DEFERRAL = /commercial (?:terms )?spec|RFC's economics section/i;
// Connect seals stored payloads as jose JWE and signs outgoing webhooks in the
// Standard Webhooks format, so a spec must not send implementers back to the
// hand-built nonce allocator, AES-GCM envelope, or body-only HMAC they replaced.
const RETIRED_CONNECT_CRYPTO =
  /MAX_ENCRYPTIONS_PER_KID|allocator reservation|\{envelope_version, algorithm, kid, nonce, ciphertext\}|existing `sha256=` lowercase-hex HMAC contract|desktop's exact\s+format|adopts this wire format verbatim/;
const DEPLOY_HOST_NAMES = "(?:vercel|netlify)";
const RETIRED_DEPLOY_TERMS =
  "(?:doors?|hooks?|webhooks?|connections?|credentials?|oauth|callbacks?|promotions?|publish[ -]events?|authority|ordering)";
const RETIRED_CONNECT_PROVIDERS = new RegExp(
  [
    "provider[\\s_-]+connection",
    "provider[ -]attest",
    "provider (?:door|hook|webhook|project|credential|authority|ordering)s?",
    "\\bprovider(?:'s)?\\s+authorization\\b",
    "\\bprovider(?:'s)?\\s+(?:oauth|connection_id)\\b",
    "\\b(?:oauth|connection_id)\\b(?:\\s+authorization)?\\s+for\\s+the\\s+provider\\b",
    "provider and generic",
    "promotion (?:event|sequence)",
    "provider_connection_id|external_project",
    "webhook reprovision|reprovision the provider",
    "/callbacks/(?:\\{provider\\}|vercel\\b|netlify\\b)",
    "project_already_claimed",
    "`promotion`",
    '"kind"\\s*:\\s*"provider"',
    `\\b${DEPLOY_HOST_NAMES}\\b(?:'s)?[ -]+(?:deploy[ -]+)?${RETIRED_DEPLOY_TERMS}\\b`,
    `\\b${RETIRED_DEPLOY_TERMS}(?:[ -]+(?:(?:for|from|on)[ -]+)?|/)${DEPLOY_HOST_NAMES}\\b`,
  ].join("|"),
  "i",
);
// desktop-repo-public-face plan Task 8 rewrites this walkthrough; exclude it here until then.
const WALKTHROUGH_PENDING_TASK_8 = `${PRODUCT_DOCS}/get-value-in-5-minutes.md`;

export function publicFaceFailures(read, exists, listFiles) {
  const failures = checkCountFailures(read, exists);

  for (const file of listFiles(
    PRODUCT_DOCS,
    (path) => path.endsWith(".md") && path !== WALKTHROUGH_PENDING_TASK_8,
  )) {
    const hit = INTENT_PHRASES.exec(read(file));
    if (hit) {
      failures.push(
        `${file} reads as product intent ("${hit[0]}"); a walkthrough describes what the app does, and intent lines belong in docs/qa/manual-testing-runbook.md.`,
      );
    }
  }

  const docsIndex = read(DOCS_INDEX);
  if (!/publication-checklist\.md\)[^\n]*historical/i.test(docsIndex)) {
    failures.push(
      `${DOCS_INDEX} must mark operations/publication-checklist.md as historical on the line that links it; the cutover ran on 2026-08-21 and the checklist is no longer an entry point.`,
    );
  }
  if (
    !docsIndex.includes("connected-service") ||
    !read(CONTRIBUTING).includes("docs/engineering/connected-service/")
  ) {
    failures.push(
      `${DOCS_INDEX} and ${CONTRIBUTING} must say the connected-service implementation specifications are public in docs/engineering/connected-service/; the old wording called them private while the files sat beside it.`,
    );
  }

  for (const file of listFiles(CONNECTED_SPECS, (path) => path.endsWith("-spec.md"))) {
    const hit = PRIVATE_RECORD_DEFERRAL.exec(read(file));
    if (hit) {
      failures.push(
        `${file} defers to a private record ("${hit[0]}"); state the rule in place, or say the value is set outside this specification.`,
      );
    }
    const retired = RETIRED_CONNECT_CRYPTO.exec(read(file));
    if (retired) {
      failures.push(
        `${file} specifies a retired Connect crypto contract ("${retired[0]}"); stored payloads are jose flattened JWE (dir, A256GCM, random IV) and outgoing webhooks use Standard Webhooks.`,
      );
    }
    const provider = RETIRED_CONNECT_PROVIDERS.exec(read(file));
    if (provider) {
      failures.push(
        `${file} specifies a retired Connect provider contract ("${provider[0]}"); deploy intake uses the generic signed door and publish-attestation ordering.`,
      );
    }
  }

  if (
    exists(LOCALHOST_FIXTURES) &&
    /https?:\/\/[a-z0-9.-]+\.(?:ai|run)\b/.test(read(LOCALHOST_FIXTURES))
  ) {
    failures.push(
      `${LOCALHOST_FIXTURES} names a real third-party domain as a test fixture; use a reserved example.com host.`,
    );
  }

  return failures;
}
