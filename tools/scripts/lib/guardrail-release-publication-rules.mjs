import { orderedBefore } from "./guardrail-text-utils.mjs";

// Split out of guardrail-release-pipeline-rules.mjs to stay under the
// per-module line budget: publication (signed checksum manifest, GitHub
// Release) and provenance attestation are one coherent rule family, both
// scoped to the publish-release job.
export function releasePublicationSafetyFailures(read) {
  const releaseWorkflow = read(".github/workflows/release.yml");
  const signerRecordScript = read(".github/scripts/release/record-signed-payload.sh");
  const verifyPayloadScript = read(".github/scripts/release/verify-signed-payload.sh");
  const verifyUnixScript = read(".github/scripts/release/verify-unix-artifacts.sh");
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };
  const jobSection = (jobName) => {
    const match = releaseWorkflow.match(
      new RegExp(`\\n  ${jobName}:\\n[\\s\\S]*?(?=\\n  [A-Za-z0-9_-]+:\\n|$)`),
    );
    return match?.[0] ?? "";
  };
  const signerJob = jobSection("sign-updaters");
  const verifierJob = jobSection("verify-release");
  const publisherJob = jobSection("publish-release");
  const verifierCommands = `${verifierJob}\n${verifyPayloadScript}\n${verifyUnixScript}`
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");

  // One signed checksum manifest per release: signed in isolation, verified
  // without secrets against every listed artifact, cross-checked against the
  // upload plan, published beside the artifacts and on the GitHub Release.
  const uploadPlanCrossCheck = `while read -r hash name; do
            grep -Fq "$(printf '\\tv%s/%s\\t%s' "$VERSION" "$name" "$hash")" publication/upload-plan.tsv`;
  check(
    signerJob.includes('"$SIGNER" signer sign "$MANIFEST"') &&
      signerJob.includes('MANIFEST="$GITHUB_WORKSPACE/signing-input/SHA256SUMS"') &&
      signerRecordScript.includes(
        'cp "signing-input/$manifest" "signed-release-payload/$manifest"',
      ) &&
      verifierCommands.includes("cmp -s checksum-signature.sig payload/SHA256SUMS.minisig") &&
      verifierCommands.includes(
        '"$verifier" "$public_key" payload/SHA256SUMS checksum-signature.sig',
      ) &&
      verifierCommands.includes(
        `expected=$(awk -v name="$(basename "$1")" '$2 == name { print $1 }' payload/SHA256SUMS)`,
      ) &&
      verifierCommands.includes('test "$(sha256_file "$1")" = "$expected"') &&
      verifierCommands.includes('verify_listed "$dir/$cli_archive"') &&
      publisherJob.includes("add_upload payload/SHA256SUMS SHA256SUMS") &&
      publisherJob.includes("add_upload payload/SHA256SUMS.minisig SHA256SUMS.minisig") &&
      publisherJob.includes(uploadPlanCrossCheck) &&
      publisherJob.includes("contents: write") &&
      publisherJob.includes("gh release create") &&
      publisherJob.includes("--verify-tag") &&
      publisherJob.includes("payload/SHA256SUMS payload/SHA256SUMS.minisig") &&
      orderedBefore(
        publisherJob,
        "https://releases.sitecmd.com/api/releases-admin",
        'gh release create "$TAG_NAME"',
      ),
    "release.yml must sign one release-wide SHA256SUMS with the production updater key, verify its .minisig without secrets and every CLI archive against it, cross-check every uploaded checksum against the upload plan, upload both beside the artifacts, and create the GitHub Release (verified tag, changelog notes, checksum assets) only after the release manifest advanced.",
  );

  // The release manifest advances before the Release is created, so a Release
  // that is missing, draft, or asset-less leaves clients offered a version they
  // cannot verify; re-running the publisher has to repair it.
  check(
    publisherJob.includes(`if [ "$(jq -r '.isDraft' release-state.json)" = "true" ]; then`) &&
      publisherJob.includes(
        `jq -e --arg name "$asset" '.assets | any(.name == $name)' release-state.json`,
      ) &&
      publisherJob.includes('gh release upload "$TAG_NAME" "payload/$asset"') &&
      publisherJob.includes("--clobber"),
    "release.yml publish-release must repair an existing Release instead of exiting clean: fail the step on a draft, and attach any missing SHA256SUMS or SHA256SUMS.minisig with gh release upload --clobber.",
  );

  // The Release notes send readers to one README section for the checksum
  // manifest; that section has to carry the steps the notes promise.
  const readmeAnchor = "README.md#verify-your-download";
  const verifySection =
    /\n## Verify your download\n[\s\S]*?(?=\n## |$)/.exec(read("README.md"))?.[0] ?? "";
  check(
    !publisherJob.includes(readmeAnchor) ||
      (verifySection.includes("minisign -Vm SHA256SUMS -x SHA256SUMS.minisig -P ") &&
        verifySection.includes("shasum -a 256 -c --ignore-missing SHA256SUMS")),
    `release.yml release notes point readers at ${readmeAnchor} to verify the signed SHA256SUMS, so that README section must carry the minisign verification of SHA256SUMS against SHA256SUMS.minisig and the checksum comparison for the downloaded file.`,
  );

  // Provenance is attested only by the credentialed publisher, after every
  // verification leg and the Release exist, never by a build or signer job.
  const nonPublisherJobs = releaseWorkflow.replace(publisherJob, "");
  const attestSubjectPaths = `          subject-path: |
            payload/*/*.tar.gz
            payload/*/*.zip
            payload/SHA256SUMS`;
  check(
    /uses: actions\/attest-build-provenance@[0-9a-f]{40}/.test(publisherJob) &&
      publisherJob.includes("id-token: write") &&
      publisherJob.includes("attestations: write") &&
      publisherJob.includes(attestSubjectPaths) &&
      !nonPublisherJobs.includes("attestations: write") &&
      !nonPublisherJobs.includes("actions/attest-build-provenance@") &&
      orderedBefore(
        publisherJob,
        'gh release create "$TAG_NAME"',
        "uses: actions/attest-build-provenance@",
      ),
    "release.yml publish-release must run a SHA-pinned actions/attest-build-provenance over every published artifact glob and the SHA256SUMS manifest, after the GitHub Release step, with id-token and attestations write scoped to that job alone.",
  );

  // Publication ends with a public smoke test: every upload-plan object
  // re-fetched and hash-matched, with the advertised latest version checked.
  check(
    publisherJob.includes("- name: Smoke test the public release surface") &&
      publisherJob.includes("done < publication/upload-plan.tsv") &&
      publisherJob.includes(
        'got=$(curl -fsSL -A "$SMOKE_UA" --retry 5 --retry-delay 3 "$url" | sha256sum | awk \'{print $1}\')',
      ) &&
      publisherJob.includes(`jq -r '.latest_version'`) &&
      publisherJob.includes('if [ "$latest" != "$VERSION" ]; then') &&
      orderedBefore(
        publisherJob,
        "uses: actions/attest-build-provenance@",
        "- name: Smoke test the public release surface",
      ) &&
      publisherJob.trimEnd().endsWith('exit "$fail"'),
    "release.yml publish-release must end with a public smoke test that re-downloads and hash-matches every upload-plan object, verifies the advertised latest version, and exits with the accumulated failure flag.",
  );

  // The releases worker keeps monitor User-Agents out of download and
  // update-check analytics, so every smoke-test request must announce one.
  const smokeStep = publisherJob.slice(
    publisherJob.indexOf("- name: Smoke test the public release surface"),
  );
  const smokeCurls = smokeStep.split("\n").filter((line) => line.includes("curl "));
  check(
    smokeStep.includes('SMOKE_UA="SiteCMD-Release-Smoke/1"') &&
      smokeCurls.length > 0 &&
      smokeCurls.every((line) => line.includes('-A "$SMOKE_UA"')),
    'release.yml\'s public smoke test must define SMOKE_UA="SiteCMD-Release-Smoke/1" and pass -A "$SMOKE_UA" on every curl request, so the releases worker keeps this synthetic traffic out of download and update-check analytics.',
  );

  return failures;
}
