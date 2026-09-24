import { orderedBefore } from "./guardrail-text-utils.mjs";
import { releasePublicationSafetyFailures } from "./guardrail-release-publication-rules.mjs";

export function releasePipelineSafetyFailures(read) {
  const releaseWorkflow = read(".github/workflows/release.yml");
  const candidateScript = read(".github/scripts/release/build-candidate-manifest.sh");
  const buildTauriScript = read(".github/scripts/release/build-tauri-app.sh");
  const buildMacosDmgScript = read(".github/scripts/release/build-macos-dmg.sh");
  const buildCliScript = read(".github/scripts/release/build-cli.sh");
  const signerInputScript = read(".github/scripts/release/stage-signer-inputs.sh");
  const signerRecordScript = read(".github/scripts/release/record-signed-payload.sh");
  const verifyPayloadScript = read(".github/scripts/release/verify-signed-payload.sh");
  const verifyUnixScript = read(".github/scripts/release/verify-unix-artifacts.sh");
  const tauriConfig = JSON.parse(read("apps/desktop/src-tauri/tauri.conf.json"));
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
  const sparseCheckoutPaths = (job) => {
    const marker = "          sparse-checkout: |\n";
    const start = job.indexOf(marker);
    if (start === -1) return [];
    const paths = [];
    for (const line of job.slice(start + marker.length).split("\n")) {
      if (!line.startsWith("            ")) break;
      paths.push(line.trim());
    }
    return paths;
  };
  const tagGateJob = jobSection("tag-gate");
  const preflightJob = jobSection("preflight");
  const candidateJob = jobSection("prepare-candidate");
  const buildJob = jobSection("build");
  const signerJob = jobSection("sign-updaters");
  const verifierJob = jobSection("verify-release");
  const publisherJob = jobSection("publish-release");
  const validateKeyJob = jobSection("validate-updater-key");
  const validatePublishKeyJob = jobSection("validate-publish-key");
  const candidateCommands = `${candidateJob}\n${candidateScript}`;
  const buildCommands = `${buildJob}\n${buildTauriScript}\n${buildMacosDmgScript}\n${buildCliScript}`;
  const signerCommands = `${signerJob}\n${signerInputScript}\n${signerRecordScript}`;
  const verifierCommands = `${verifierJob}\n${verifyPayloadScript}\n${verifyUnixScript}`
    .split("\n")
    .filter((line) => !line.trimStart().startsWith("#"))
    .join("\n");

  for (const [job, script] of [
    [candidateJob, ".github/scripts/release/build-candidate-manifest.sh"],
    [buildJob, ".github/scripts/release/build-tauri-app.sh"],
    [buildJob, ".github/scripts/release/build-macos-dmg.sh"],
    [buildJob, ".github/scripts/release/locate-updater-bundle.sh"],
    [buildJob, ".github/scripts/release/build-cli.sh"],
    [signerJob, ".github/scripts/release/stage-signer-inputs.sh"],
    [signerJob, ".github/scripts/release/record-signed-payload.sh"],
    [verifierJob, ".github/scripts/release/verify-signed-payload.sh"],
    [verifierJob, ".github/scripts/release/verify-unix-artifacts.sh"],
  ]) {
    check(
      job.includes(`run: bash ${script}`),
      `release.yml must invoke the reviewed release helper ${script}.`,
    );
  }
  for (const [jobName, job] of [
    ["sign-updaters", signerJob],
    ["verify-release", verifierJob],
  ]) {
    check(
      sparseCheckoutPaths(job).includes(".github/scripts/release"),
      `release.yml ${jobName} must include .github/scripts/release in its sparse checkout before invoking release helpers.`,
    );
  }

  check(
    preflightJob.includes("needs: tag-gate") &&
      candidateJob.includes("needs: preflight") &&
      buildJob.includes(
        "[prepare-candidate, validate-updater-key, validate-publish-key, publish-capability-manifest]",
      ) &&
      orderedBefore(releaseWorkflow, "\n  preflight:\n", "\n  prepare-candidate:\n") &&
      orderedBefore(releaseWorkflow, "\n  prepare-candidate:\n", "\n  build:\n") &&
      preflightJob.includes("pnpm guardrails:repo") &&
      preflightJob.includes("pnpm run legal:check") &&
      preflightJob.includes("pnpm test") &&
      preflightJob.includes("pnpm run audit:deps:js") &&
      preflightJob.includes("pnpm run audit:deps:signer") &&
      preflightJob.includes("pnpm run audit:deps:rust") &&
      preflightJob.includes("cargo nextest run --no-fail-fast --workspace --profile ci") &&
      preflightJob.includes("cargo clippy --no-deps --workspace --all-targets -- -D warnings") &&
      preflightJob.includes("cargo fmt --check --all"),
    "Release workflow must run tests, guardrails, legal-artifact checks, workspace and updater-signer dependency audits, and Rust gates before building signed updater artifacts.",
  );

  const requiredLicenseEnv =
    "SITECMD_REQUIRE_LICENSE_CONFIG SITECMD_LICENSE_STORE_ID SITECMD_LICENSE_CORE_MONTHLY_VARIANT_ID SITECMD_LICENSE_CORE_ANNUAL_VARIANT_ID SITECMD_LICENSE_PRO_MONTHLY_VARIANT_ID SITECMD_LICENSE_PRO_ANNUAL_VARIANT_ID SITECMD_LICENSE_CORE_CHECKOUT_URL SITECMD_LICENSE_PRO_CHECKOUT_URL";
  for (const required of requiredLicenseEnv.split(" ")) {
    check(buildJob.includes(required), `Release workflow must pass ${required}.`);
  }

  // Re-fetch the annotated tag object before verification; checkout may leave
  // the local tag ref pointing directly at its commit.
  const tagFetchIndex = tagGateJob.indexOf(
    'git fetch --force origin "refs/tags/${TAG_NAME}:refs/tags/${TAG_NAME}"',
  );
  const tagVerifyIndex = tagGateJob.indexOf('git verify-tag "$TAG_NAME"');
  check(
    tagFetchIndex !== -1 && tagVerifyIndex !== -1 && tagFetchIndex < tagVerifyIndex,
    "release.yml tag-gate must re-fetch the annotated tag object from origin before git verify-tag; actions/checkout leaves the local tag ref pointing at the commit, so verification otherwise fails on every signed release.",
  );

  check(
    tagGateJob.includes("git merge-base --is-ancestor") &&
      tagGateJob.includes('if [ -z "$ALLOWED_SIGNERS" ]') &&
      tagGateJob.includes("exit 1"),
    "release.yml must require a release commit from the default branch and fail closed when the allowed tag-signers list is absent.",
  );

  // The trusted signer list must come from protected environment state, not the
  // commit whose signature it authenticates.
  check(
    tagGateJob.includes("environment: release-tag-trust") &&
      tagGateJob.includes("${{ vars.RELEASE_ALLOWED_SIGNERS }}") &&
      tagGateJob.includes("normalize_signers .github/allowed-signers") &&
      tagGateJob.includes('cmp -s "$REVIEWED_SIGNERS_FILE" "$PROTECTED_SIGNERS_FILE"') &&
      tagGateJob.includes('gpg.ssh.allowedSignersFile "$PROTECTED_SIGNERS_FILE"') &&
      !tagGateJob.includes("allowedSignersFile .github/allowed-signers"),
    "release.yml tag-gate must verify with the protected release-tag-trust signer list and fail when it drifts from the reviewed .github/allowed-signers mirror.",
  );

  // Bind the reviewed candidate to source, workflow, lockfiles, version, and notes.
  check(
    candidateCommands.includes("release-candidate/manifest.json") &&
      candidateCommands.includes("workflow_sha256") &&
      candidateCommands.includes("pnpm_lock_sha256") &&
      candidateCommands.includes("cargo_lock_sha256") &&
      candidateCommands.includes('if [ "$VERSION" != "$APP_VERSION" ]') &&
      candidateCommands.includes('if [ "$TAG_COMMIT" != "$SOURCE_COMMIT" ]') &&
      // Checkout already fetched the tag; this credential-free job must not re-fetch it.
      !candidateCommands.includes("git fetch") &&
      candidateCommands.includes(
        'node ./tools/scripts/check-changelog-notes.mjs --release-notes "$VERSION"',
      ) &&
      !candidateCommands.includes("%(contents:"),
    "release.yml must create a source- and workflow-bound immutable candidate, and read versioned changelog notes without exposing the signed-tag signature block.",
  );

  check(
    buildJob.includes("name: release-signing") &&
      buildJob.includes("Bind build to the human-reviewed candidate") &&
      buildJob.includes("Build Tauri app with ephemeral updater key") &&
      buildCommands.includes("tauri signer generate") &&
      // `tauri build` consumes TAURI_SIGNING_PRIVATE_KEY, not the signer CLI's path flag.
      buildCommands.includes('TAURI_SIGNING_PRIVATE_KEY="$EPHEMERAL_KEY"') &&
      !buildJob.includes("${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}") &&
      !buildJob.includes("${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}"),
    "release.yml product builds must require candidate approval, use only a throwaway updater key, and exclude reusable updater secrets.",
  );

  check(
    buildJob.includes("GOOGLE_CLIENT_ID: ${{ secrets.GOOGLE_CLIENT_ID }}") &&
      buildJob.includes("GOOGLE_CLIENT_SECRET: ${{ secrets.GOOGLE_CLIENT_SECRET }}") &&
      buildCommands.includes("node tools/scripts/check-google-oauth-config.mjs"),
    "release.yml product builds must supply both Google Desktop OAuth credentials and validate them before packaging.",
  );

  // Expose the permanent updater key only to its probe and isolated signer.
  check(
    signerJob.includes("needs: [prepare-candidate, build]") &&
      signerJob.includes("name: release-updater-signing") &&
      signerJob.includes("${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}") &&
      signerJob.includes("${{ secrets.TAURI_SIGNING_PRIVATE_KEY_PASSWORD }}") &&
      signerJob.includes("Validate and stage signer inputs without secrets") &&
      signerJob.includes("Sign exact updater and CLI bytes with the production key") &&
      signerCommands.includes("artifact_sha256") &&
      signerCommands.includes("source_commit") &&
      validateKeyJob.includes("name: release-updater-signing") &&
      validateKeyJob.includes("${{ secrets.TAURI_SIGNING_PRIVATE_KEY }}") &&
      (releaseWorkflow.match(/\$\{\{ secrets\.TAURI_SIGNING_PRIVATE_KEY \}\}/g) || []).length ===
        2 &&
      (releaseWorkflow.match(/\$\{\{ secrets\.TAURI_SIGNING_PRIVATE_KEY_PASSWORD \}\}/g) || [])
        .length === 2 &&
      orderedBefore(releaseWorkflow, "\n  build:\n", "\n  sign-updaters:\n"),
    "release.yml must expose the permanent updater key only inside the release-updater-signing environment (the pre-build probe and the post-build isolated signer) and record the exact signed artifact hash.",
  );

  check(
    buildJob.includes("SITECMD_SOURCE_COMMIT:") &&
      signerCommands.includes("signing-input/$target/$cli_archive") &&
      signerCommands.includes('test -s "$cli_sig_file"') &&
      verifierCommands.includes('"$dir/$cli_archive.sig"') &&
      verifierCommands.includes('"$dir/$cli_archive" cli-signature.sig') &&
      publisherJob.includes('add_upload "$dir/$cli_archive.sig" "$cli_archive.sig"'),
    "release.yml must embed its source commit and sign, verify, and publish every CLI archive signature beside the archive.",
  );

  // Signed-checksum publication and provenance attestation live in their own
  // module (guardrail-release-publication-rules.mjs) to stay under the line
  // budget; merge their failures in here so callers see one combined list.
  failures.push(...releasePublicationSafetyFailures(read));

  check(
    verifierJob.includes("needs: [prepare-candidate, sign-updaters]") &&
      verifierJob.includes("Build the minimal secretless verifier") &&
      verifierJob.includes("Verify payload hashes, provenance, and updater signature") &&
      !verifierJob.includes("${{ secrets.") &&
      orderedBefore(releaseWorkflow, "\n  sign-updaters:\n", "\n  verify-release:\n"),
    "release.yml must verify signed payloads and platform signatures in a secretless job after updater signing.",
  );

  check(
    verifierCommands.includes("codesign --verify --strict cli-check/sitecmd") &&
      verifierCommands.includes('test "$cli_team" = "$app_team"') &&
      verifierCommands.includes("$cliSignature = Get-AuthenticodeSignature $cli") &&
      verifierCommands.includes('$cliSignature.Status -ne "Valid"') &&
      verifierCommands.includes(
        "$cliSignature.SignerCertificate.Thumbprint -ne $signature.SignerCertificate.Thumbprint",
      ) &&
      orderedBefore(
        verifierCommands,
        "codesign --verify --strict cli-check/sitecmd",
        'test "$(cli-check/sitecmd --version)"',
      ) &&
      orderedBefore(
        verifierCommands,
        "$cliSignature = Get-AuthenticodeSignature $cli",
        "$actual = & $cli --version",
      ),
    "release.yml must verify the extracted macOS CLI with codesign and the extracted Windows CLI with Authenticode, bind each to the app's signer, and do so before executing either binary.",
  );

  // The releases worker verifies a GitHub Actions OIDC token minted for its
  // audience in release-publish on a v* tag; no stored key authenticates.
  const releasesTokenRequest =
    'curl -sS -H "Authorization: bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=https://releases.sitecmd.com"';
  const presentsReleasesToken = (source) =>
    source.includes(releasesTokenRequest) && source.includes('"Authorization: Bearer ${token}"');
  const advanceManifestStep =
    /\n {6}- name: Advance the production updater manifest\n[\s\S]*?(?=\n {6}- |$)/.exec(
      publisherJob,
    )?.[0] ?? "";
  check(
    publisherJob.includes("needs: [prepare-candidate, verify-release]") &&
      publisherJob.includes("name: release-publish") &&
      publisherJob.includes("\n      id-token: write\n") &&
      presentsReleasesToken(advanceManifestStep) &&
      !publisherJob.includes("uses: actions/checkout@") &&
      orderedBefore(releaseWorkflow, "\n  verify-release:\n", "\n  publish-release:\n"),
    "release.yml must publish only after every secretless verification leg, advance the updater manifest with the job's own releases-audience OIDC token (id-token: write), and must not check out or execute product source in the credentialed publisher.",
  );

  // Retain prior signing keys; the lookbehind distinguishes overwrite from append.
  const releaseRunbook = read("docs/operations/releasing.md");
  check(
    !/(?<!>)>\s*\.github\/allowed-signers/.test(releaseRunbook),
    "docs/operations/releasing.md must append to .github/allowed-signers with `>>`; `>` discards the key that signed every existing release tag.",
  );

  const allowedSigners = read(".github/allowed-signers");
  const signerKeys = allowedSigners
    .split("\n")
    .filter((line) => line.trim() && !line.trim().startsWith("#"));
  check(
    signerKeys.length > 0,
    ".github/allowed-signers must list at least one signing key; an empty trust file fails every release tag.",
  );

  // Validate the updater key before spending time on platform builds.
  check(
    validateKeyJob.includes("release-updater-signing") &&
      validateKeyJob.includes("signer sign") &&
      orderedBefore(releaseWorkflow, "\n  validate-updater-key:\n", "\n  build:\n"),
    "Release workflow must keep the validate-updater-key probe job (release-updater-signing environment, tauri signer sign) so a bad signing secret fails in seconds instead of after every platform build.",
  );

  // Authenticate the publish token with a non-mutating request before building.
  check(
    validatePublishKeyJob.includes("name: release-publish") &&
      validatePublishKeyJob.includes("\n      id-token: write\n") &&
      presentsReleasesToken(validatePublishKeyJob) &&
      validatePublishKeyJob.includes('!= "400"') &&
      releaseWorkflow.split(releasesTokenRequest).length - 1 === 2 &&
      orderedBefore(releaseWorkflow, "\n  validate-publish-key:\n", "\n  build:\n"),
    "Release workflow must keep the validate-publish-key probe job (release-publish environment, id-token: write, invalid-body POST with the releases-audience OIDC token expecting 400) so a token the releases worker refuses fails in seconds instead of after every platform build.",
  );

  // The AWS CLI requires a region even when pointed at R2.
  check(
    publisherJob.includes("AWS_DEFAULT_REGION: auto"),
    "release.yml publish job must set AWS_DEFAULT_REGION (R2 takes \"auto\"): without it the AWS CLI fails with 'You must specify a region' after every platform build has already succeeded.",
  );

  // Normalize Windows CRLF before GNU base64 decoding.
  for (const [file, source] of [
    [".github/workflows/release.yml", releaseWorkflow],
    [".github/scripts/release/build-tauri-app.sh", buildTauriScript],
    [".github/scripts/release/verify-signed-payload.sh", verifyPayloadScript],
  ]) {
    for (const [index, line] of source.split("\n").entries()) {
      if (line.includes("base64 --decode") && !line.includes("tr -d '\\r'")) {
        failures.push(
          `${file} line ${index + 1}: every \`base64 --decode\` must strip carriage returns first (\`tr -d '\\r' |\`); a raw pipe on the Windows runner delivers CRLF and GNU base64 rejects it after the tag is already pushed.`,
        );
      }
    }
  }

  // The separate CLI build step needs its own compile-time environment values.
  const cliStepStart = buildJob.indexOf("- name: Build CLI (headless scanner)");
  const cliStep =
    cliStepStart === -1
      ? ""
      : buildJob.slice(cliStepStart, buildJob.indexOf("run: |", cliStepStart));
  const cliBuildBlock =
    cliStepStart === -1
      ? ""
      : `${buildJob.slice(
          cliStepStart,
          buildJob.indexOf("\n      - name: Save platform fragment", cliStepStart),
        )}\n${buildCliScript}`;
  check(
    cliStepStart !== -1,
    "release.yml: the standalone CLI build step is gone or renamed, so the rule that keeps its compile-time configuration in step with the app's cannot check anything.",
  );
  for (const [variable, why] of [
    ["SITECMD_CONNECTED_ENDPOINT", "`sitecmd gate` cannot reach the service without it"],
  ]) {
    check(
      cliStep.includes(`${variable}:`),
      `release.yml: the standalone CLI build step must set ${variable}, because ${why}. It is read through option_env! at compile time, so an unset variable is a binary that builds and then refuses at runtime.`,
    );
  }
  check(
    !cliStep.includes("SITECMD_REQUIRE_LICENSE_CONFIG") &&
      !cliStep.includes("SITECMD_LICENSE_STORE_ID"),
    "release.yml: the free local CLI build must not require desktop license configuration; connected commands authenticate with site-scoped credentials.",
  );

  check(
    buildJob.includes("tool: cargo-license") &&
      cliBuildBlock.includes("cargo license --manifest-path") &&
      cliBuildBlock.includes('"$GITHUB_WORKSPACE/THIRD_PARTY_DEPENDENCIES.json"') &&
      cliBuildBlock.includes('"$GITHUB_WORKSPACE/THIRD_PARTY_LICENSES.txt"') &&
      cliBuildBlock.includes(
        "CLI_LEGAL_FILES=(LICENSE NOTICE THIRD_PARTY_NOTICES THIRD_PARTY_DEPENDENCIES.json THIRD_PARTY_LICENSES.txt THIRD_PARTY_LICENSES.tsv)",
      ) &&
      verifierCommands.includes(
        "for legal_file in LICENSE NOTICE THIRD_PARTY_NOTICES THIRD_PARTY_DEPENDENCIES.json THIRD_PARTY_LICENSES.txt THIRD_PARTY_LICENSES.tsv",
      ) &&
      verifierCommands.includes(
        'foreach ($legalFile in @("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES", "THIRD_PARTY_DEPENDENCIES.json", "THIRD_PARTY_LICENSES.txt", "THIRD_PARTY_LICENSES.tsv"))',
      ),
    "CLI archive must include notices, a dependency inventory, upstream license texts, and its platform inventory; release verification must inspect them after extraction.",
  );

  const desktopResources = tauriConfig.bundle?.resources ?? {};
  check(
    desktopResources["../../../LICENSE"] === "LICENSE" &&
      desktopResources["../../../NOTICE"] === "NOTICE" &&
      desktopResources["../../../THIRD_PARTY_NOTICES"] === "THIRD_PARTY_NOTICES" &&
      desktopResources["../../../THIRD_PARTY_DEPENDENCIES.json"] ===
        "THIRD_PARTY_DEPENDENCIES.json" &&
      desktopResources["../../../THIRD_PARTY_LICENSES.txt"] === "THIRD_PARTY_LICENSES.txt",
    "Desktop bundle must include notices, a dependency inventory, and upstream license texts as readable resources.",
  );

  return failures;
}
