/** Return the Rust documentation and attributes directly above an item. */
export function attributeBlock(source, index) {
  const prefix = source.slice(0, index);
  const blank = prefix.lastIndexOf("\n\n");
  return blank === -1 ? prefix : prefix.slice(blank);
}

// Return one Rust constant table through its closing bracket.
function tableBlock(source, tableConst) {
  const start = source.indexOf(tableConst);
  if (start === -1) return null;
  const end = source.indexOf("\n];", start);
  return source.slice(start, end === -1 ? source.length : end);
}

/** Return literal manifest ids claimed by a runner table. */
export function claimedChecks(source, tableConst) {
  const table = tableBlock(source, tableConst);
  if (table === null) return null;
  const claimed = [];
  for (const [, body] of table.matchAll(/covers:\s*&\[([^\]]*)\]/g)) {
    for (const [, id] of body.matchAll(/"([^"]+)"/g)) claimed.push(id);
  }
  return claimed;
}

/** Return explicit check exclusions and reasons from one table. */
export function excludedChecks(source, tableConst) {
  const block = tableBlock(source, tableConst);
  if (block === null) return null;
  return [...block.matchAll(/\(\s*"([^"]+)",\s*\n?\s*"([^"]*)",?\s*\)/g)].map((match) => ({
    check: match[1],
    reason: match[2],
  }));
}

const FREE_FUNCTION_COVERS = [
  ["accessibility.axe."],
  [
    "performance.cls",
    "performance.fcp",
    "performance.lcp",
    "performance.long_task_blocking",
    "polish.js-errors",
  ],
  ["performance.page_weight"],
  ["security.ssl.chain", "security.ssl.expiry", "security.ssl.hostname", "security.ssl.protocol"],
];

/** Return check types and the count of runner rows requiring desktop registration. */
export function runnerDispatches(source, tableConst) {
  const table = tableBlock(source, tableConst);
  if (table === null) return null;
  // Separate closure shapes to avoid nested quantifiers; free-function rows yield no type.
  const types = [
    ...table.matchAll(/run: \|inputs\| ([\w:]+)(?:\.run|::evaluate)\(/g),
    ...table.matchAll(/run: \|inputs\| \{\n\s*([\w:]+)(?:\.run|::evaluate)\(/g),
  ].map((match) => match[1].split("::").pop());
  const freeFunctions = [...table.matchAll(/covers:\s*&\[([^\]]*)\],\s*run:\s*\|inputs\|/g)].filter(
    (match) => {
      const covers = [...match[1].matchAll(/"([^"]+)"/g)].map((id) => id[1]);
      return FREE_FUNCTION_COVERS.some(
        (ids) => ids.length === covers.length && ids.every((id) => covers.includes(id)),
      );
    },
  ).length;
  return { types, invocations: [...table.matchAll(/\brun:\s*\|inputs\|/g)].length - freeFunctions };
}

/** Return whether a fetch plan can supply every fact required by an entry. */
export function isFetchPlannable(entry) {
  const requires = entry.requires ?? [];
  return (
    requires.length > 0 && requires.every((fact) => fact === "page_artifact" || fact === "fetch")
  );
}

/** One claimed-or-excluded audit over a lane. */
export function laneCoverageFailures({ lane, entries, claimed, excluded, table, subject }) {
  const failures = [];
  const excludedIds = new Set(excluded.map((entry) => entry.check));
  const claimedSet = new Set(claimed);
  const unclaimed = entries
    .map((entry) => entry.check)
    .filter((check) => !claimedSet.has(check) && !excludedIds.has(check));
  if (unclaimed.length > 0) {
    failures.push(
      `these ${lane}-lane checks have no ${subject} in ${table} and no documented exclusion, so a ` +
        `hosted scan would report nothing for them while the manifest claims it can produce them: ` +
        unclaimed.sort().join(", "),
    );
  }
  const duplicated = claimed.filter((check, index) => claimed.indexOf(check) !== index);
  if (duplicated.length > 0) {
    failures.push(
      `${table}: these ids are claimed by more than one ${subject}, which would emit their rows ` +
        `twice: ${[...new Set(duplicated)].sort().join(", ")}`,
    );
  }
  const unreasoned = excluded.filter((entry) => entry.reason.trim().length === 0);
  if (unreasoned.length > 0) {
    failures.push(
      `${table}: these exclusions carry no reason, which makes a coverage hole look like a ` +
        `decision: ${unreasoned.map((entry) => entry.check).join(", ")}`,
    );
  }
  const both = claimed.filter((check) => excludedIds.has(check));
  if (both.length > 0) {
    failures.push(
      `${table}: these ids are both claimed and excluded, so one of the two statements is a lie: ` +
        `${[...new Set(both)].sort().join(", ")}`,
    );
  }
  return failures;
}

// Read string entries from a Rust `= &[...]` constant.
export function constList(source, name) {
  const start = source.indexOf(name);
  if (start === -1) return null;
  // Start after the type annotation's own brackets.
  const open = source.indexOf("= &[", start);
  const close = source.indexOf("]", open);
  if (open === -1 || close === -1) return null;
  return [...source.slice(open, close).matchAll(/"([^"]+)"/g)].map((match) => match[1]);
}
