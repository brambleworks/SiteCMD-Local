import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { digest } from "../lib/workflow-plan.mjs";

const manifest = JSON.parse(readFileSync(new URL("../cases/onekey-runtime.json", import.meta.url)));
const manifestId = digest(manifest);

export function onekeyRuntimeTreeDigest(directory) {
  const root = realpathSync(directory);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.uid !== 0 || rootMetadata.mode & 0o022) {
    throw new Error("OneKey runtime root is not controller-owned and read-only");
  }
  const entries = [];
  let bytes = 0;

  function visit(name) {
    const target = path.join(root, name);
    const metadata = lstatSync(target);
    const mode = metadata.mode & 0o7777;
    if (metadata.uid !== 0 || (!metadata.isSymbolicLink() && mode & 0o022)) {
      throw new Error(`OneKey runtime entry is not controller-owned and read-only: ${name}`);
    }
    if (entries.length >= 30_000) throw new Error("OneKey runtime file count exceeds its bound");
    if (metadata.isSymbolicLink()) {
      const resolved = realpathSync(target);
      if (!resolved.startsWith(`${root}/`) && !/^\/usr\/bin\/python3(?:\.12)?$/.test(resolved)) {
        throw new Error(`OneKey runtime link points outside its allowed roots: ${name}`);
      }
      entries.push({ name, mode, link: readlinkSync(target) });
      return;
    }
    if (metadata.isDirectory()) {
      entries.push({ name, mode, directory: true });
      for (const child of readdirSync(target).sort()) visit(`${name}/${child}`);
      return;
    }
    if (!metadata.isFile() || metadata.nlink !== 1) {
      throw new Error(`Unsupported OneKey runtime entry: ${name}`);
    }
    // codeql-allow: js/file-system-race
    const handle = openSync(target, constants.O_RDONLY | constants.O_NOFOLLOW);
    try {
      const opened = fstatSync(handle);
      if (
        !opened.isFile() ||
        opened.nlink !== 1 ||
        opened.ino !== metadata.ino ||
        opened.dev !== metadata.dev ||
        opened.uid !== 0 ||
        opened.mode & 0o022
      ) {
        throw new Error(`OneKey runtime entry changed while it was read: ${name}`);
      }
      bytes += opened.size;
      if (bytes > 256 * 1024 * 1024) throw new Error("OneKey runtime exceeds its size bound");
      entries.push({
        name,
        mode: opened.mode & 0o7777,
        sha256: digest(readFileSync(handle)),
      });
    } finally {
      closeSync(handle);
    }
  }

  for (const name of ["requirements.lock", "venv"]) visit(name);
  return digest(entries);
}

function installedPackages(directory) {
  const script =
    "import json; from importlib.metadata import distributions; " +
    "print(json.dumps(dict(sorted((d.metadata['Name'].lower().replace('_','-'), d.version) for d in distributions()))))";
  const result = spawnSync(`${directory}/venv/bin/python`, ["-B", "-c", script], {
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 1024 * 1024,
    env: { PATH: "/usr/bin:/bin", PYTHONDONTWRITEBYTECODE: "1" },
  });
  if (result.status !== 0) throw new Error("OneKey runtime inventory could not be verified");
  return JSON.parse(result.stdout);
}

function pythonIdentity(directory) {
  const binary = realpathSync(`${directory}/venv/bin/python`);
  if (!/^\/usr\/bin\/python3(?:\.12)?$/.test(binary)) {
    throw new Error("OneKey runtime Python points outside the expected system installation");
  }
  const result = spawnSync(`${directory}/venv/bin/python`, ["--version"], {
    encoding: "utf8",
    timeout: 15_000,
    maxBuffer: 1024 * 1024,
    env: { PATH: "/usr/bin:/bin" },
  });
  const version = `${result.stdout}${result.stderr}`.trim();
  if (result.status !== 0 || version !== manifest.python) {
    throw new Error("OneKey runtime Python version differs from its manifest");
  }
  return { binary, version, sha256: digest(readFileSync(binary)) };
}

export function inspectOnekeyRuntime() {
  const directory = manifest.directory;
  if (realpathSync(directory) !== directory) throw new Error("OneKey runtime path changed");
  const lockSha256 = digest(readFileSync(`${directory}/requirements.lock`));
  const packages = installedPackages(directory);
  const python = pythonIdentity(directory);
  if (lockSha256 !== manifest.lockSha256 || digest(packages) !== digest(manifest.packages)) {
    throw new Error("OneKey runtime dependencies differ from their manifest");
  }
  const content = {
    schemaVersion: 1,
    id: manifestId,
    directory,
    lockSha256,
    packages,
    python,
    treeSha256: onekeyRuntimeTreeDigest(directory),
  };
  return { ...content, sha256: digest(content) };
}

export function verifyOnekeyRuntime(runtime) {
  const { sha256, ...content } = runtime ?? {};
  if (
    runtime?.schemaVersion !== 1 ||
    runtime.id !== manifestId ||
    runtime.directory !== manifest.directory ||
    runtime.lockSha256 !== manifest.lockSha256 ||
    digest(runtime.packages) !== digest(manifest.packages) ||
    runtime.python?.version !== manifest.python ||
    digest(pythonIdentity(runtime.directory)) !== digest(runtime.python) ||
    sha256 !== digest(content) ||
    realpathSync(runtime.directory) !== runtime.directory ||
    onekeyRuntimeTreeDigest(runtime.directory) !== runtime.treeSha256
  ) {
    throw new Error("OneKey qualification requires its frozen runtime receipt");
  }
  return runtime;
}
