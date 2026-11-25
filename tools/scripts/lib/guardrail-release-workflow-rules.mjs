import { releasePipelineSafetyFailures } from "./guardrail-release-pipeline-rules.mjs";

export function releaseWorkflowSafetyFailures(read, { releaseWorkflow = true } = {}) {
  const failures = releaseWorkflow ? releasePipelineSafetyFailures(read) : [];
  const releaseRunbook = read("docs/operations/releasing.md");
  if (/(?<!>)>\s*\.github\/allowed-signers/.test(releaseRunbook)) {
    failures.push(
      "docs/operations/releasing.md must append to .github/allowed-signers with `>>`; `>` discards the key that signed every existing release tag.",
    );
  }
  const allowedSigners = read(".github/allowed-signers");
  if (!allowedSigners.split("\n").some((line) => line.trim() && !line.trim().startsWith("#"))) {
    failures.push(
      ".github/allowed-signers must list at least one signing key; an empty trust file fails every release tag.",
    );
  }
  return failures;
}
