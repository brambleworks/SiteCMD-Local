export function releaseArtifactSafetyFailures(read, exists, listFiles) {
  const failures = [];
  const check = (condition, message) => {
    if (!condition) failures.push(message);
  };

  // Tauri bundles every app-package binary, so tools belong in examples or sibling crates.
  const appBinDir = "apps/desktop/src-tauri/src/bin";
  const strayAppBins = exists(appBinDir) ? listFiles(appBinDir, (f) => f.endsWith(".rs")) : [];
  check(
    strayAppBins.length === 0,
    `apps/desktop/src-tauri/src/bin must contain no Rust binaries (found: ${strayAppBins.join(", ")}). Put dev tools in apps/desktop/src-tauri/examples/ and shipped tools in a separate workspace package so tauri-bundler never ships them in the app.`,
  );

  // Only the isolated publisher may upload immutable, hash-verified artifacts.
  const releaseWorkflow = read(".github/workflows/release.yml");
  const macosDmgScript = read(".github/scripts/release/build-macos-dmg.sh");
  const releaseScript = read("tools/scripts/release.mjs");
  const tagReleaseScript = read("tools/scripts/tag-release.mjs");
  const publicHistoryScript = read("tools/scripts/prepare-public-history.mjs");
  const rootPackage = read("package.json");
  const signedReleaseTag =
    // The notes template must end with a newline: verbatim cleanup keeps the
    // message byte-exact, and without the terminator the signature block lands
    // on the last message line where git cannot find it.
    /\["tag",\s*"-s",\s*"--cleanup=verbatim",\s*"-m",\s*`Release \$\{tag\}`,\s*"-m",\s*`\$\{releaseNotes\}\\n`,\s*tag\]/.test(
      tagReleaseScript,
    );
  const desktopBuildScript = read("apps/desktop/src-tauri/build_config.rs");
  const connectedClient = read("apps/desktop/src-tauri/src/connected_service.rs");
  const jobSection = (jobName) => {
    const match = releaseWorkflow.match(
      new RegExp(`\\n  ${jobName}:\\n[\\s\\S]*?(?=\\n  [A-Za-z0-9_-]+:\\n|$)`),
    );
    return match?.[0] ?? "";
  };
  const publishJob = jobSection("publish-release");
  const publishProbeJob = jobSection("validate-publish-key");
  const nonPublisherWorkflow = releaseWorkflow.replace(publishJob, "").replace(publishProbeJob, "");
  check(
    publishJob.includes("needs: [prepare-candidate, verify-release]") &&
      publishJob.includes("name: release-publish") &&
      publishJob.includes("aws s3api head-object --bucket sitecmd-releases") &&
      publishJob.includes('aws s3 cp "s3://sitecmd-releases/$object_key" "$existing"') &&
      publishJob.includes('if [ "$actual_hash" != "$expected_hash" ]') &&
      publishJob.includes("already exists with different bytes") &&
      publishJob.includes('aws s3 cp "$local_path" "s3://sitecmd-releases/$object_key"') &&
      !publishJob.includes("uses: actions/checkout@") &&
      !nonPublisherWorkflow.includes("aws s3 cp ") &&
      !nonPublisherWorkflow.includes("${{ secrets.R2_ACCESS_KEY_ID }}") &&
      !nonPublisherWorkflow.includes("${{ secrets.R2_SECRET_ACCESS_KEY }}") &&
      !nonPublisherWorkflow.includes("${{ secrets.R2_ACCOUNT_ID }}") &&
      !nonPublisherWorkflow.includes("${{ secrets.RELEASE_ADMIN_KEY }}") &&
      publishProbeJob.includes("name: release-publish") &&
      !publishProbeJob.includes("${{ secrets.R2_ACCESS_KEY_ID }}") &&
      !publishProbeJob.includes("${{ secrets.R2_SECRET_ACCESS_KEY }}") &&
      !publishProbeJob.includes("${{ secrets.R2_ACCOUNT_ID }}"),
    "release.yml must keep R2 and manifest-promotion credentials in the checkout-free publish-release job, after secretless verification, and hash-compare any existing object before upload; RELEASE_ADMIN_KEY alone may also appear in the release-publish-environment validate-publish-key probe, which must hold no R2 credentials.",
  );
  check(
    signedReleaseTag &&
      tagReleaseScript.includes('if (branch !== "main")') &&
      tagReleaseScript.includes('"refs/remotes/origin/main"') &&
      tagReleaseScript.includes("if (head !== originMain)") &&
      !tagReleaseScript.includes('git", ["push"'),
    "tools/scripts/tag-release.mjs must create a signed annotated tag with verbatim changelog notes only from a clean main commit that exactly matches origin/main, and it must never push.",
  );
  check(
    releaseScript.includes("prepareChangelogRelease") &&
      releaseScript.includes('const CHANGELOG_FILE = "CHANGELOG.md"') &&
      releaseScript.includes("fs.writeFileSync(path.join(ROOT, CHANGELOG_FILE)") &&
      releaseScript.includes('branch === "main" || !branch.startsWith("release/")') &&
      !releaseScript.includes("--allow-branch") &&
      !releaseScript.includes("--no-git") &&
      !releaseScript.includes('gitRun("commit"') &&
      !releaseScript.includes('gitRun("tag"'),
    "tools/scripts/release.mjs must prepare version and changelog changes only on a clean release/* branch; it must never commit, tag, or permit a main-branch override.",
  );
  check(
    rootPackage.includes('"release:tag": "node ./tools/scripts/tag-release.mjs"') &&
      rootPackage.includes(
        '"publication:prepare": "node ./tools/scripts/prepare-public-history.mjs"',
      ) &&
      publicHistoryScript.includes('["status", "--porcelain", "--untracked-files=all"]') &&
      publicHistoryScript.includes('["symbolic-ref", "--short", "HEAD"]') &&
      publicHistoryScript.includes("if (!options.apply) return") &&
      publicHistoryScript.includes("--confirm-rewrite-main") &&
      publicHistoryScript.includes('["bundle", "create", backup, "--all", "HEAD"]') &&
      publicHistoryScript.includes('["bundle", "verify", backup]') &&
      publicHistoryScript.includes('["bundle", "list-heads", backup]') &&
      publicHistoryScript.includes(
        "local refs changed while the private bundle was being created",
      ) &&
      publicHistoryScript.includes(
        '["commit-tree", "-S", details.tree, "-m", "Publish SiteCMD source"]',
      ) &&
      publicHistoryScript.includes('"verify-commit", commit') &&
      publicHistoryScript.includes('["update-ref", "refs/heads/main", commit, details.head]') &&
      publicHistoryScript.includes('["update-ref", "refs/heads/main", details.head, commit]') &&
      publicHistoryScript.includes('["tools/scripts/check-publication-history.mjs", commit]') &&
      !publicHistoryScript.includes('["push"') &&
      !publicHistoryScript.includes('["tag", "-d"') &&
      !publicHistoryScript.includes('["branch", "-D"'),
    "the publication helper must default to a dry run, require a clean main and explicit confirmation, verify an external all-ref backup, create and verify an exact-tree signed root commit, move main with compare-and-swap plus rollback, run the history gate, and never push or delete refs.",
  );
  check(
    connectedClient.includes('option_env!("SITECMD_CONNECTED_ENDPOINT")') &&
      desktopBuildScript.includes('"SITECMD_CONNECTED_ENDPOINT"') &&
      releaseWorkflow.includes('SITECMD_CONNECTED_ENDPOINT: "https://connect.sitecmd.com"'),
    "release.yml and build.rs must bake SITECMD_CONNECTED_ENDPOINT (https://connect.sitecmd.com) into shipped desktop builds; otherwise Connected renders but every sync is disabled.",
  );

  // Hash-pin dmgbuild because it processes the signed release artifact.
  const joinedWorkflow = `${releaseWorkflow}\n${macosDmgScript}`.replace(/\\\n\s*/g, " ");
  check(
    joinedWorkflow.includes('--require-hashes -r "$SRC/branding/dmgbuild-requirements.txt"') &&
      !/\binstall\b[^\n]*\bdmgbuild\b(?!-requirements\.txt)/.test(joinedWorkflow),
    "release.yml must install dmgbuild only via --require-hashes -r $SRC/branding/dmgbuild-requirements.txt; a bare pip install of dmgbuild runs unpinned PyPI code against the artifact signed with the Developer ID.",
  );

  return failures;
}
