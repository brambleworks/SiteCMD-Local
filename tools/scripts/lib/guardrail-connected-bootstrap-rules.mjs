const BOOTSTRAP = "apps/desktop/src-tauri/src/db/connected_bootstrap.rs";
const REGISTRY = "apps/desktop/src-tauri/src/db/mod.rs";

// Wire vocabulary belongs to the payload builder, not local derivation.
const WIRE_WORDS = ["claimed_fixed", "verified_fixed", "query_dependent", "location_hash"];

// Test modules may drive stores directly.
function isProdRustFile(file) {
  if (/[/\\]tests[/\\]/.test(file)) return false;
  return !/(_tests?\.rs|^tests\.rs)$/.test(file.split(/[/\\]/).pop());
}

// Remove line comments before structural matching.
function codeOnly(source) {
  return source
    .split("\n")
    .filter((line) => !/^\s*\/\//.test(line))
    .join("\n");
}

// Return a Rust function through its matching closing brace.
function functionBody(source, name) {
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

function count(source, pattern) {
  return (source.match(pattern) || []).length;
}

/**
 * @param {(file: string) => string} read
 * @param {(file: string) => boolean} exists
 * @param {(dir: string, predicate: (file: string) => boolean) => string[]} listFiles
 */
export function connectedBootstrapFailures(read, exists, listFiles, extraRoots = []) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const source = (file) => (exists(file) ? read(file) : "");

  const bootstrap = source(BOOTSTRAP);
  const code = codeOnly(bootstrap);

  const derive = functionBody(bootstrap, "derive_bootstrap_set");
  check(
    derive !== null && /read_projection\(/.test(derive) && /read_overrides\(/.test(derive),
    `${BOOTSTRAP} derive_bootstrap_set must union the current projection with the eligible lifecycle overrides. The projection alone loses every terminal group, and the overrides alone leave the service to meet ordinary open issues later as new findings.`,
  );
  check(
    derive !== null && /unchecked_transaction/.test(derive),
    `${BOOTSTRAP} derive_bootstrap_set must read the group set and the evidence in one transaction. A scan committing between them produces a snapshot carrying occurrences of a group the set never declared.`,
  );
  check(
    derive !== null && /!draft\.present && draft\.state\.is_none\(\)/.test(derive),
    `${BOOTSTRAP} must skip a group with neither an open row nor an override. It was fixed by a scan and never decided about, so declaring it reports a fix as an open issue.`,
  );

  const projection = functionBody(bootstrap, "read_projection");
  check(
    projection !== null &&
      /FROM work_items/.test(projection) &&
      /resolved_at IS NULL/.test(projection),
    `${BOOTSTRAP} read_projection must read the open work_items projection, which is the same predicate the issues list groups by.`,
  );
  const overrides = functionBody(bootstrap, "read_overrides");
  check(
    overrides !== null && /FROM project_issue_states/.test(overrides),
    `${BOOTSTRAP} read_overrides must read lifecycle overrides, including the terminal groups whose findings are gone.`,
  );

  check(
    !/INSERT INTO|UPDATE |DELETE FROM/.test(code),
    `${BOOTSTRAP} must write nothing. It states what is already true; a derivation that also changes state cannot be run to preview what would be sent.`,
  );
  check(
    !/effective|now_ms/.test(code),
    `${BOOTSTRAP} must declare the stored state, not the effective one. The server evaluates snooze expiry at read time, so collapsing it here discards the policy and reads as a reopening nobody decided.`,
  );

  check(
    /pub enum BootstrapState/.test(bootstrap) && /^\s*Regressed,/m.test(bootstrap),
    `${BOOTSTRAP} BootstrapState must be able to express a regression: reading one is exactly what a producer has to do at bootstrap.`,
  );
  check(
    count(bootstrap, /-> Result<BootstrapState/g) === 1,
    `${BOOTSTRAP} must build a BootstrapState in exactly one place, by decoding a stored row. A second constructor is a caller asserting a state instead of reporting one.`,
  );
  const decode = functionBody(bootstrap, "state_from_row");
  check(
    decode !== null &&
      /snooze_until\.ok_or_else/.test(decode) &&
      /verified_by\.ok_or_else/.test(decode),
    `${BOOTSTRAP} state_from_row must refuse a dismissal or verification it cannot describe rather than repairing it. An invented deadline either silences the group past what the user asked for or reopens it immediately.`,
  );

  for (const word of WIRE_WORDS) {
    check(
      !new RegExp(word).test(code),
      `${BOOTSTRAP} mentions ${word}: the wire mapping belongs to the payload builder. This module derives the local facts it reads, and a second mapping is how two of them start disagreeing.`,
    );
  }
  const lineCounting = new Set([
    "line: Option<u32>,",
    "if entry.code_instances.insert((row.line, row.finding_id)) {",
    "|(check_id, rule, path, line, finding_id, severity, confidence)| FindingRow {",
    "line,",
    "finding.confidence, finding.line,",
    "line: row.get(6)?,",
    "finding.severity, finding.confidence, finding.line,",
  ]);
  const identityCode = code
    .split("\n")
    .filter((line) => !lineCounting.has(line.trim()))
    .join("\n");
  const identity = /pub (?:enum OccurrenceLocation|struct OccurrenceIdentity) \{[^]*?\n\}/g;
  check(
    !/\bline\b/.test(identityCode) &&
      [...bootstrap.matchAll(identity)].every(
        ([definition]) => !/\bline\b/.test(codeOnly(definition)),
      ),
    `${BOOTSTRAP} must not carry a line number into an occurrence identity. Lines churn under ordinary editing, and an identity that dies whenever a neighbor moves cannot support verification.`,
  );
  check(
    /File \{\s*rule: String,\s*path: String,?\s*\}/.test(bootstrap),
    `${BOOTSTRAP} a code occurrence is the producer rule and the repository-relative path, and nothing else. Multiplicity is preserved as instance_count.`,
  );
  check(
    [...bootstrap.matchAll(identity)].every(
      ([definition]) => !/\b(?:finding_id|occurrence_id)\b/.test(codeOnly(definition)),
    ),
    `${BOOTSTRAP} local finding IDs belong only in instance counting and must stay out of the occurrence identity.`,
  );

  // Evidence reads require actionable verdicts from complete runs.
  const findingQueries = count(code, /FROM scan_findings|JOIN scan_findings/g);
  check(
    findingQueries >= 3 && count(code, /verdict IN \('fail', 'warn'\)/g) >= findingQueries,
    `${BOOTSTRAP} must read only actionable findings. A passing check is evidence that the issue is absent, and reporting it as an occurrence inverts the meaning of the snapshot.`,
  );
  check(
    count(code, /status = 'complete'/g) >= findingQueries,
    `${BOOTSTRAP} must read only complete runs. A failed or partial collector proves nothing, and its findings are not the picture the service should be handed.`,
  );

  const lastKnown = functionBody(bootstrap, "last_known_occurrences");
  check(
    lastKnown !== null &&
      /PARTITION BY check_id\b/.test(lastKnown) &&
      /ORDER BY started_at DESC, execution_id DESC/.test(lastKnown),
    `${BOOTSTRAP} last_known_occurrences must pick the newest EXECUTION that saw the group. The verifier needs all observations from that execution.`,
  );

  const latest = functionBody(bootstrap, "latest_evidence");
  check(
    projection !== null &&
      /source = 'code_scan'/.test(projection) &&
      lastKnown !== null &&
      count(lastKnown, /run\.source = 'code_scan'/g) === 2 &&
      latest !== null &&
      count(latest, /\bsource = 'code_scan'/g) === 3 &&
      !/ScanEvidenceSource::WebScan/.test(code),
    `${BOOTSTRAP} must derive local evidence and groups from code scans only.`,
  );

  const registry = source(REGISTRY);
  check(
    /mod connected_bootstrap;/.test(registry) && /BootstrapSet/.test(registry),
    `${REGISTRY} must register the bootstrap derivation, or nothing can read what a connection would send.`,
  );

  // One derivation, and never on the CI path.
  const rustFiles = ["apps/desktop/src-tauri/src", ...extraRoots].flatMap((dir) =>
    listFiles(dir, (file) => file.endsWith(".rs")),
  );
  check(
    rustFiles.length > 100,
    `connected-bootstrap guardrail scanned only ${rustFiles.length} Rust files; the enumeration broke. Update guardrail-connected-bootstrap-rules.mjs.`,
  );
  for (const file of rustFiles) {
    if (file === BOOTSTRAP || !isProdRustFile(file)) continue;
    check(
      !/fn derive_bootstrap_set/.test(read(file)),
      `${file} defines a second bootstrap derivation. Two answers to "what does this site look like" is how a submission declares a group set the app never showed.`,
    );
  }
  const ciFiles = [
    ...listFiles("apps/desktop/src-tauri/src/cli", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/crates/cli/src", (file) => file.endsWith(".rs")),
  ];
  check(
    ciFiles.length > 0,
    "connected-bootstrap guardrail found no CLI sources; update guardrail-connected-bootstrap-rules.mjs.",
  );
  for (const file of ciFiles) {
    check(
      !/derive_bootstrap_set/.test(read(file)),
      `${file} derives a bootstrap set: a CI checkout has no lifecycle store to bootstrap from, and a submission from one cannot create groups.`,
    );
  }

  return failures;
}
