// The npm distribution ships the release CLI binaries as @sitecmd/cli plus
// one platform package per target. The binaries arrive only at publish time,
// so the skeleton in packaging/npm/ must stay coherent by inspection: the
// launcher must map exactly the platform packages that exist, the versions
// must stay on the CI-stamped placeholder, and the release workflow must
// still run the publish script after the canonical release is live.

const NPM_DIR = "packaging/npm";
const PLACEHOLDER = "0.0.0-dev";
const MAIN = `${NPM_DIR}/cli`;
const PLATFORMS = {
  "cli-darwin-universal": { os: ["darwin"], cpu: ["x64", "arm64"], bin: "sitecmd" },
  "cli-linux-x64": { os: ["linux"], cpu: ["x64"], bin: "sitecmd" },
  "cli-linux-arm64": { os: ["linux"], cpu: ["arm64"], bin: "sitecmd" },
  "cli-win32-x64": { os: ["win32"], cpu: ["x64"], bin: "sitecmd.exe" },
};

function parse(read, path, failures) {
  try {
    return JSON.parse(read(path));
  } catch (error) {
    failures.push(`${path} is missing or unparseable (${error.message})`);
    return null;
  }
}

export function npmCliPackageFailures(read) {
  const failures = [];

  const main = parse(read, `${MAIN}/package.json`, failures);
  if (main) {
    if (main.name !== "@sitecmd/cli" || main.version !== PLACEHOLDER) {
      failures.push(
        `${MAIN}/package.json must be @sitecmd/cli at the ${PLACEHOLDER} placeholder; CI stamps the release version at publish time`,
      );
    }
    if (main.bin?.sitecmd !== "bin/sitecmd.js") {
      failures.push(`${MAIN}/package.json must expose bin.sitecmd = bin/sitecmd.js`);
    }
    const wanted = Object.keys(PLATFORMS).map((p) => `@sitecmd/${p}`);
    const declared = Object.entries(main.optionalDependencies ?? {});
    if (
      declared.length !== wanted.length ||
      !declared.every(([name, version]) => wanted.includes(name) && version === PLACEHOLDER)
    ) {
      failures.push(
        `${MAIN}/package.json optionalDependencies must be exactly ${wanted.join(", ")} at ${PLACEHOLDER}`,
      );
    }
    if (main.license !== "Apache-2.0") {
      failures.push(`${MAIN}/package.json must carry the repository's Apache-2.0 license`);
    }
  }

  let shim = "";
  try {
    shim = read(`${MAIN}/bin/sitecmd.js`);
  } catch (error) {
    failures.push(`${MAIN}/bin/sitecmd.js is missing (${error.message})`);
  }
  if (shim) {
    const mentioned = new Set(
      [...shim.matchAll(/@sitecmd\/(cli-[a-z0-9-]+)/g)].map(([, name]) => name),
    );
    for (const platform of Object.keys(PLATFORMS)) {
      if (!mentioned.has(platform)) {
        failures.push(`${MAIN}/bin/sitecmd.js never maps @sitecmd/${platform}`);
      }
      mentioned.delete(platform);
    }
    for (const extra of mentioned) {
      failures.push(
        `${MAIN}/bin/sitecmd.js maps @sitecmd/${extra}, which has no package under ${NPM_DIR}/`,
      );
    }
  }

  for (const [platform, expected] of Object.entries(PLATFORMS)) {
    const pkg = parse(read, `${NPM_DIR}/${platform}/package.json`, failures);
    if (!pkg) continue;
    if (pkg.name !== `@sitecmd/${platform}` || pkg.version !== PLACEHOLDER) {
      failures.push(
        `${NPM_DIR}/${platform}/package.json must be @sitecmd/${platform} at the ${PLACEHOLDER} placeholder`,
      );
    }
    if (
      JSON.stringify(pkg.os) !== JSON.stringify(expected.os) ||
      JSON.stringify(pkg.cpu) !== JSON.stringify(expected.cpu)
    ) {
      failures.push(
        `${NPM_DIR}/${platform}/package.json os/cpu must be ${JSON.stringify(expected.os)}/${JSON.stringify(expected.cpu)} so npm installs it only where the binary runs`,
      );
    }
    if (!(pkg.files ?? []).includes("bin/") || !(pkg.files ?? []).includes("NOTICE")) {
      failures.push(
        `${NPM_DIR}/${platform}/package.json files must ship bin/ and the Apache NOTICE`,
      );
    }
  }

  let script = "";
  try {
    script = read(".github/scripts/release/publish-npm-packages.sh");
  } catch (error) {
    failures.push(`.github/scripts/release/publish-npm-packages.sh is missing (${error.message})`);
  }
  if (script) {
    for (const [platform, expected] of Object.entries(PLATFORMS)) {
      if (!script.includes(`stage_platform ${platform} `)) {
        failures.push(`publish-npm-packages.sh never stages ${platform}`);
      }
      if (platform === "cli-win32-x64" && !script.includes(expected.bin)) {
        failures.push(`publish-npm-packages.sh must stage the Windows binary as ${expected.bin}`);
      }
    }
    if (!script.includes("--provenance")) {
      failures.push("publish-npm-packages.sh must publish with npm provenance attestation");
    }
  }

  const workflow = read(".github/workflows/release.yml");
  const job = workflow.slice(workflow.indexOf("\n  publish-npm:"));
  if (!job.includes("publish-npm:")) {
    failures.push(".github/workflows/release.yml has no publish-npm job");
  } else {
    if (!/needs:\s*\[prepare-candidate, publish-release\]/.test(job)) {
      failures.push(
        "publish-npm must depend on publish-release so npm never leads the canonical release channel",
      );
    }
    if (!job.includes("publish-npm-packages.sh")) {
      failures.push("publish-npm must run .github/scripts/release/publish-npm-packages.sh");
    }
  }

  return failures;
}
