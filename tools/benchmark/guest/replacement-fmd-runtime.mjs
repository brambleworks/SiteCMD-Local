import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { digest } from "../lib/workflow-plan.mjs";
import { verifyBrowserRuntime } from "./browser-runtime.mjs";

const manifest = JSON.parse(readFileSync(new URL("../cases/fmd-runtime.json", import.meta.url)));
const manifestId = digest(manifest);

export function fmdReferenceTreeDigest(directory) {
  const root = realpathSync(directory);
  const rootMetadata = lstatSync(root);
  if (!rootMetadata.isDirectory() || rootMetadata.uid !== 0 || rootMetadata.mode & 0o022) {
    throw new Error("FMD reference runtime root is not controller-owned and read-only");
  }
  const entries = [];
  let bytes = 0;

  function visit(name) {
    const target = path.join(root, name);
    const metadata = lstatSync(target);
    const mode = metadata.mode & 0o7777;
    if (metadata.uid !== 0 || (!metadata.isSymbolicLink() && metadata.mode & 0o022)) {
      throw new Error(`FMD reference entry is not controller-owned and read-only: ${name}`);
    }
    if (entries.length >= 2_000) throw new Error("FMD reference file count exceeds its bound");
    if (metadata.isSymbolicLink()) {
      throw new Error(`FMD reference runtime contains an unsupported link: ${name}`);
    }
    if (metadata.isDirectory()) {
      entries.push({ name, mode, directory: true });
      for (const child of readdirSync(target).sort()) visit(`${name}/${child}`);
      return;
    }
    if (!metadata.isFile() || metadata.nlink !== 1) {
      throw new Error(`FMD reference runtime contains an unsupported entry: ${name}`);
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
        throw new Error(`FMD reference entry changed while it was read: ${name}`);
      }
      bytes += opened.size;
      if (bytes > 64 * 1024 * 1024) throw new Error("FMD reference runtime exceeds its bound");
      entries.push({
        name,
        mode: opened.mode & 0o7777,
        sha256: digest(readFileSync(handle)),
      });
    } finally {
      closeSync(handle);
    }
  }

  for (const name of ["baseline", "reference", "details-reference"]) visit(name);
  return digest(entries);
}

export function verifyFmdBrowserRuntime(runtime) {
  const reference = runtime?.reference;
  const { sha256, treeSha256, ...installation } = reference ?? {};
  if (!/^[a-f0-9]{24}$/.test(reference?.installationId ?? "")) {
    throw new Error("FMD browser grading requires a distinct reference installation");
  }
  const directory = `/opt/sitecmd-benchmark/fmd-runtimes/${manifestId}/${reference.installationId}`;
  if (
    runtime.schemaVersion !== 1 ||
    runtime.kind !== "fmd-browser-v1" ||
    reference.schemaVersion !== 1 ||
    reference.id !== manifestId ||
    reference.directory !== directory ||
    reference.baselineSha256 !== manifest.baselineSha256 ||
    reference.referenceSha256 !== manifest.referenceSha256 ||
    sha256 !== digest({ ...installation, treeSha256 }) ||
    realpathSync(directory) !== directory ||
    digest(JSON.parse(readFileSync(`${directory}/receipt.json`))) !== digest(installation) ||
    fmdReferenceTreeDigest(directory) !== treeSha256
  ) {
    throw new Error("FMD reference runtime changed after it was frozen");
  }
  verifyBrowserRuntime(runtime.browser);
  return runtime;
}

export function fmdRuntimeManifest() {
  return structuredClone(manifest);
}
