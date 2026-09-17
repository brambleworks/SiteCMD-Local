// Static half: every required check must come from a workflow that runs on
// every pull request, or GitHub waits forever on the pull requests its path,
// branch, or event filter skips. Live half: the settings SECURITY.md and the
// docs promise, including which refs each ruleset actually governs.

function pullRequestTriggerBody(source) {
  const trigger = /^ {2}pull_request:(.*)$/m.exec(source);
  if (!trigger) return null;
  const rest = source.slice(trigger.index + trigger[0].length);
  return rest.split(/^ {0,2}[a-z_-]+:/m)[0];
}

/** Returns the pull_request `types` list, or null when the trigger omits it. */
function pullRequestTypes(body) {
  const inline = /^ {4}types: *\[(.*)\] *$/m.exec(body);
  if (inline) {
    return inline[1]
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
  }
  const start = body.search(/^ {4}types: *$/m);
  if (start === -1) return null;
  const values = [];
  for (const line of body.slice(start).split("\n").slice(1)) {
    const item = /^ {6}- (.+)$/.exec(line);
    if (!item) break;
    values.push(item[1].trim());
  }
  return values;
}

// A required check has to report on every pull request, so its workflow may not
// filter the trigger by path or branch, and must still fire on the two events
// that open and update one.
function runsOnEveryPullRequest(source) {
  const body = pullRequestTriggerBody(source);
  if (body === null) return false;
  if (/^ {4}(?:paths|paths-ignore|branches|branches-ignore):/m.test(body)) return false;
  const types = pullRequestTypes(body);
  return types === null || ["opened", "synchronize"].every((event) => types.includes(event));
}

function jobNames(source) {
  return [...source.matchAll(/^ {4}name: (.+)$/gm)].map((match) => match[1].trim());
}

function matrixValues(source, key) {
  const start = source.search(new RegExp(`^ {8}${key}:\\s*$`, "m"));
  if (start === -1) return [];
  const values = [];
  for (const line of source.slice(start).split("\n").slice(1)) {
    const item = /^ {10}- (.+)$/.exec(line);
    if (!item) break;
    values.push(item[1].trim());
  }
  return values;
}

function jobNameMatches(template, context, source) {
  if (template === context) return true;
  const matrix = /^(.*)\$\{\{ matrix\.([a-z_]+) \}\}(.*)$/.exec(template);
  if (!matrix) return false;
  const [, prefix, key, suffix] = matrix;
  return matrixValues(source, key).some((value) => `${prefix}${value}${suffix}` === context);
}

export function requiredCheckWorkflowFailures(contract, read, listFiles) {
  const failures = [];
  const workflows = listFiles(".github/workflows", (file) => /\.ya?ml$/.test(file)).map((file) => ({
    file,
    source: read(file),
  }));
  for (const context of contract.branchRuleset.requiredStatusChecks) {
    const owners = workflows.filter(({ source }) =>
      jobNames(source).some((name) => jobNameMatches(name, context, source)),
    );
    if (owners.length === 0) {
      failures.push(
        `required check "${context}" names no job in .github/workflows; GitHub would wait for it forever.`,
      );
      continue;
    }
    if (!owners.some(({ source }) => runsOnEveryPullRequest(source))) {
      failures.push(
        `required check "${context}" comes from a filtered pull_request trigger (${owners
          .map((owner) => owner.file)
          .join(
            ", ",
          )}); a path, branch, or types filter leaves pull requests that never report it and cannot merge.`,
      );
    }
  }
  return failures;
}

export function liveRepositoryProtectionFailures(contract, live) {
  const failures = [];
  if (live.privateVulnerabilityReporting !== true) {
    failures.push(
      "Private vulnerability reporting is disabled; SECURITY.md and the issue chooser route reporters to it.",
    );
  }
  for (const [setting, expected] of Object.entries(contract.securityAndAnalysis)) {
    const actual = live.securityAndAnalysis?.[setting]?.status ?? "missing";
    if (actual !== expected) {
      failures.push(`security_and_analysis.${setting} is ${actual}; expected ${expected}.`);
    }
  }
  for (const expected of [contract.branchRuleset, contract.tagRuleset]) {
    const ruleset = live.rulesets.find((candidate) => candidate.name === expected.name);
    if (!ruleset) {
      failures.push(`ruleset "${expected.name}" does not exist.`);
      continue;
    }
    if (ruleset.enforcement !== "active") {
      failures.push(`ruleset "${expected.name}" is ${ruleset.enforcement}, not active.`);
    }
    if ((ruleset.bypass_actors ?? []).length > 0) {
      failures.push(
        `ruleset "${expected.name}" grants bypass actors; administrators must be included.`,
      );
    }
    if (ruleset.target !== expected.target) {
      failures.push(
        `ruleset "${expected.name}" targets ${ruleset.target ?? "nothing"}, not ${expected.target}; it governs refs the contract does not.`,
      );
    }
    for (const key of ["include", "exclude"]) {
      const actual = [...(ruleset.conditions?.ref_name?.[key] ?? [])].sort().join(", ");
      const wanted = [...expected[key === "include" ? "refNameInclude" : "refNameExclude"]]
        .sort()
        .join(", ");
      if (actual !== wanted) {
        failures.push(
          `ruleset "${expected.name}" ref_name.${key} is [${actual}]; the contract says [${wanted}].`,
        );
      }
    }
    const types = new Set((ruleset.rules ?? []).map((rule) => rule.type));
    for (const type of expected.ruleTypes) {
      if (!types.has(type))
        failures.push(`ruleset "${expected.name}" is missing the ${type} rule.`);
    }
    if (expected.requiredStatusChecks) {
      const rule = (ruleset.rules ?? []).find(
        (candidate) => candidate.type === "required_status_checks",
      );
      const contexts = new Set(
        (rule?.parameters?.required_status_checks ?? []).map((check) => check.context),
      );
      for (const context of expected.requiredStatusChecks) {
        if (!contexts.has(context)) {
          failures.push(`ruleset "${expected.name}" does not require "${context}".`);
        }
      }
    }
  }
  return failures;
}

// The contract's repository name is load-bearing well beyond documentation.
// GitHub redirects a renamed repository's web and git paths, so a stale name
// keeps working everywhere a human clicks - and fails everywhere a machine
// compares the string. The v1.4.0 release tag died on exactly that: the
// repository had become SiteCMD-app months earlier while the connect manifest
// registry's publisher allowlist and the npm packaging manifests still said
// SiteCMD, so the capability manifest was refused as unprovenanced and the
// CLI's npm provenance would have been refused after it. Nothing in the tree
// disagreed with itself, which is why nothing caught it.
//
// These rules make the next rename fail here instead, in a cascade: the
// contract must name the repository this checkout actually belongs to, and
// every reference to one of our own repositories must use the name the
// contract gives. Updating the contract after a rename is therefore not a
// one-line edit that leaves the references behind; it turns every stale
// reference into a failure until it moves too.
const REPOSITORY_URL = "github.com/";
const ACTION_USES = "uses: ";

/** Every reference to a repository owned by `owner`, as it appears in a link or
 *  an action `uses:` ref - the two shapes a machine compares rather than
 *  follows. Slugs carry a trailing `.git` in npm manifests and trailing
 *  punctuation in prose, so both are trimmed. */
export function ownedRepositoryReferences(owner, files) {
  const references = [];
  for (const { file, source } of files) {
    source.split("\n").forEach((raw, index) => {
      // A regex literal writes the same reference with its slashes and dots
      // escaped, and the rename that prompted this rule hid in exactly that
      // shape: a guardrail asserting the advisories link matched the old name
      // through an escaped pattern that no plain-text search for the slug
      // could see. Unescaping first means one scan reads both spellings.
      const text = raw.replace(/\\([./])/g, "$1");
      for (const prefix of [REPOSITORY_URL, ACTION_USES]) {
        let at = text.indexOf(`${prefix}${owner}/`);
        for (; at !== -1; at = text.indexOf(`${prefix}${owner}/`, at + 1)) {
          const start = at + prefix.length + owner.length + 1;
          const name = /^[A-Za-z0-9._-]+/.exec(text.slice(start))?.[0] ?? "";
          const trimmed = name.replace(/\.git$/, "").replace(/[.]+$/, "");
          if (trimmed) references.push({ file, line: index + 1, slug: `${owner}/${trimmed}` });
        }
      }
    });
  }
  return references;
}

export function repositoryNameFailures(contract, observed) {
  const failures = [];
  const [owner] = contract.repository.split("/");
  const checkout = observed.checkoutRepository;
  // Only when the owner matches: a contributor's fork is a different owner and
  // has nothing to say about our contract, while a rename keeps the owner and
  // is the case worth failing on.
  if (checkout && checkout !== contract.repository && checkout.startsWith(`${owner}/`)) {
    failures.push(
      `this checkout belongs to ${checkout} but .github/repository-protection.json names ${contract.repository}. ` +
        "GitHub redirects the old path, so links keep working, but the release pipeline compares the name as a string: " +
        "the connect manifest registry's publisher allowlist, npm provenance, and `uses:` action refs all refuse a mismatch.",
    );
  }
  if (observed.labelsRepository !== contract.repository) {
    failures.push(
      `.github/repository-labels.json names ${observed.labelsRepository}; the protection contract names ${contract.repository}.`,
    );
  }
  const allowed = new Set([contract.repository, ...(contract.referencedRepositories ?? [])]);
  for (const { file, line, slug } of observed.references) {
    if (!allowed.has(slug)) {
      failures.push(
        `${file}:${line} references ${slug}; this repository is ${contract.repository}. ` +
          "Add a sibling to referencedRepositories in the contract if the reference is deliberate.",
      );
    }
  }
  return failures;
}
