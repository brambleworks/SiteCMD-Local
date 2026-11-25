import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import path from "node:path";

const ENGINE_MINISIGN_PUBLIC_KEY = "RWRqdn8vDzLelbGjbzmogzz77nLG0LH9m9v59gYHmF+jRgfvwtpSo8yj";
const RELEASE_ORIGIN = "https://releases.sitecmd.com";
const MODULE_PATH = "engine/local-engine.wasm";
const MODULE = path.basename(MODULE_PATH);
const LICENSES = `${MODULE}.LICENSES.txt`;

function releaseFor(version) {
  const [core, prerelease] = typeof version === "string" ? version.split(/-(.*)/s) : [];
  if (
    !/^\d+\.\d+\.\d+$/.test(core ?? "") ||
    (prerelease !== undefined && !/^[0-9A-Za-z.-]+$/.test(prerelease))
  ) {
    throw new Error("Expected an engine version in MAJOR.MINOR.PATCH[-prerelease] form.");
  }
  return {
    version,
    abi_version: 2,
    url: `${RELEASE_ORIGIN}/engine/v${version}/${MODULE}`,
    github_release: {
      repository: "brambleworks/SiteCMD-Engine-Releases",
      tag: `engine-v${version}`,
    },
  };
}

async function readLock(root) {
  let lock;
  try {
    lock = JSON.parse(await readFile(path.join(root, "engine.lock"), "utf8"));
  } catch (error) {
    throw new Error(`Cannot read engine.lock: ${error.message}`, { cause: error });
  }
  const release = releaseFor(lock?.version);
  if (
    typeof lock.sha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(lock.sha256) ||
    lock.abi_version !== release.abi_version ||
    lock.url !== release.url ||
    lock.github_release?.repository !== release.github_release.repository ||
    lock.github_release?.tag !== release.github_release.tag
  ) {
    throw new Error("Invalid engine.lock digest, ABI, or module release coordinates.");
  }
  return lock;
}

function redactDownloadCredentials(message) {
  const credentials = [
    process.env.SITECMD_ENGINE_TOKEN,
    process.env.GH_TOKEN,
    process.env.GITHUB_TOKEN,
    process.env.GH_ENTERPRISE_TOKEN,
    process.env.GITHUB_ENTERPRISE_TOKEN,
  ]
    .filter(Boolean)
    .sort((first, second) => second.length - first.length);
  for (const credential of credentials) message = message.replaceAll(credential, "[redacted]");
  return message;
}

function digestMismatch(actual, expected) {
  return new Error(`Engine SHA-256 ${actual} does not match engine.lock (${expected}).`, {
    cause: "digest-mismatch",
  });
}

async function download(lock, asset, directory, expectedSha256) {
  const token = process.env.SITECMD_ENGINE_TOKEN ?? "";
  const destination = path.join(directory, asset);
  if (!token) {
    let bytes;
    try {
      // codeql-allow: js/file-access-to-http. The request names the version engine.lock
      // pins, and releaseFor refuses anything but MAJOR.MINOR.PATCH[-prerelease] on the
      // fixed release origin.
      const response = await fetch(releaseFor(lock.version).url + asset.slice(MODULE.length), {
        signal: AbortSignal.timeout(60_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      bytes = Buffer.from(await response.arrayBuffer());
    } catch (error) {
      const detail = [error?.message ?? String(error), error?.cause?.message]
        .filter(Boolean)
        .join(": ");
      console.warn(
        redactDownloadCredentials(
          `Public download of ${asset} failed: ${detail}. Trying the GitHub release.`,
        ),
      );
    }
    if (bytes) {
      const actual = createHash("sha256").update(bytes).digest("hex");
      if (expectedSha256 !== undefined && actual !== expectedSha256) {
        throw digestMismatch(actual, expectedSha256);
      }
      // codeql-allow: js/http-to-file-access. The bytes land in a staging folder. A fetch
      // has already matched them to the SHA-256 engine.lock pins, and a bump checks their
      // minisign signature before anything is renamed into place.
      await writeFile(destination, bytes);
      return destination;
    }
  }

  const { repository, tag } = lock.github_release;
  const result = spawnSync(
    "gh",
    ["release", "download", tag, "--repo", repository, "--pattern", asset, "--dir", directory],
    {
      env: { ...process.env, GH_TOKEN: token, GH_PROMPT_DISABLED: "1" },
      stdio: ["ignore", "ignore", "pipe"],
      encoding: "utf8",
      timeout: 120_000,
    },
  );
  if (result.status !== 0) {
    const status = result.error?.code ?? `exit ${result.status}`;
    const stderr = result.stderr?.trim();
    const message = `Could not download ${asset} from ${repository} at ${tag} using gh (${status}).`;
    throw new Error(redactDownloadCredentials(stderr ? `${message} ${stderr}` : message));
  }
  return destination;
}

async function withStagingDirectory(root, use) {
  const engineDir = path.dirname(path.join(root, MODULE_PATH));
  await mkdir(engineDir, { recursive: true });
  const staging = await mkdtemp(path.join(engineDir, ".download-"));
  try {
    return await use(staging, engineDir);
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

async function digest(file) {
  return createHash("sha256")
    .update(await readFile(file))
    .digest("hex");
}

export async function fetchEngine(root) {
  const lock = await readLock(root);
  await withStagingDirectory(root, async (staging, engineDir) => {
    const destination = path.join(engineDir, MODULE);
    let module;
    try {
      module = await download(lock, MODULE, staging, lock.sha256);
    } catch (error) {
      if (error.cause === "digest-mismatch") await rm(destination, { force: true });
      throw error;
    }
    const actual = await digest(module);
    if (actual !== lock.sha256) {
      await rm(destination, { force: true });
      throw digestMismatch(actual, lock.sha256);
    }
    await rename(module, destination);
  });
  return lock;
}

function verifySignature(file, signature, publicKey, version) {
  const result = spawnSync("minisign", ["-V", "-Q", "-P", publicKey, "-m", file, "-x", signature], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });
  if (result.status !== 0) {
    throw new Error(
      `Could not verify the signature of ${path.basename(file)} with minisign (${result.error?.code ?? `exit ${result.status}`}).`,
    );
  }
  if (result.stdout.trimEnd() !== `sitecmd local engine v${version}`) {
    throw new Error(
      `The signature of ${path.basename(file)} does not match engine version ${version}.`,
    );
  }
}

export async function bumpEngine(root, version, publicKey) {
  if (!publicKey)
    throw new Error("ENGINE_MINISIGN_PUBLIC_KEY is empty. Configure it before using --bump.");
  const release = releaseFor(version);
  return withStagingDirectory(root, async (staging, engineDir) => {
    for (const asset of [MODULE, LICENSES]) {
      const file = await download(release, asset, staging);
      const signature = await download(release, `${asset}.minisig`, staging);
      verifySignature(file, signature, publicKey, version);
    }
    const module = path.join(staging, MODULE);
    const lock = { version, sha256: await digest(module), ...release };
    const stagedLock = path.join(staging, "engine.lock");
    await writeFile(stagedLock, `${JSON.stringify(lock, null, 2)}\n`);
    await rename(module, path.join(engineDir, MODULE));
    await rename(path.join(staging, LICENSES), path.join(engineDir, LICENSES));
    await rename(stagedLock, path.join(root, "engine.lock"));
    return lock;
  });
}

if (import.meta.main) {
  try {
    const args = process.argv.slice(2);
    if (args[0] === "--") args.shift();
    const root = process.cwd();
    let lock;
    if (args.length === 0) {
      lock = await fetchEngine(root);
    } else if (args.length === 2 && args[0] === "--bump") {
      lock = await bumpEngine(root, args[1], ENGINE_MINISIGN_PUBLIC_KEY);
    } else {
      throw new Error("Usage: pnpm engine:fetch [-- --bump <version>]");
    }
    console.log(`Engine ${lock.version} SHA-256 ${lock.sha256}`);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
