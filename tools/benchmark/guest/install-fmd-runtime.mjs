import { randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import {
  materializeRepositoryFiles,
  validateRepositoryFiles,
  validateRepositorySnapshot,
} from "../lib/repository-snapshot.mjs";
import { digest } from "../lib/workflow-plan.mjs";
import { captureBrowserRuntime } from "./browser-runtime.mjs";
import {
  fmdReferenceTreeDigest,
  fmdRuntimeManifest,
  verifyFmdBrowserRuntime,
} from "./replacement-fmd-runtime.mjs";

if (process.platform !== "linux" || process.arch !== "arm64" || process.getuid() !== 0) {
  throw new Error("FMD runtime installation requires the isolated ARM64 guest controller");
}
const { baseline: rawBaseline, reference } = JSON.parse(readFileSync(0, "utf8"));
const baseline = validateRepositorySnapshot(rawBaseline);
const manifest = fmdRuntimeManifest();
const { sha256: referenceSha256, ...referenceContent } = reference ?? {};
validateRepositoryFiles(reference?.files);
if (
  baseline.sha256 !== manifest.baselineSha256 ||
  referenceSha256 !== manifest.referenceSha256 ||
  referenceSha256 !== digest(referenceContent) ||
  reference.baselineSha256 !== baseline.sha256 ||
  reference.kind !== "implementation-regions" ||
  JSON.stringify(reference.editableFiles) !== JSON.stringify([manifest.entry])
) {
  throw new Error("FMD baseline or reference differs from its runtime manifest");
}
const baselineFiles = new Map(baseline.files.map((file) => [file.name, file]));
const referenceFiles = new Map(reference.files.map((file) => [file.name, file]));
const original = Buffer.from(baselineFiles.get(manifest.entry)?.base64 ?? "", "base64").toString();
const fixed = Buffer.from(referenceFiles.get(manifest.entry)?.base64 ?? "", "base64").toString();
if (
  original.split(manifest.unsafeAssignment).length !== 2 ||
  fixed !== original.replace(manifest.unsafeAssignment, manifest.safeAssignment) ||
  baselineFiles.size !== referenceFiles.size ||
  [...baselineFiles].some(([name, file]) =>
    name === manifest.entry
      ? false
      : file.mode !== referenceFiles.get(name)?.mode ||
        file.base64 !== referenceFiles.get(name)?.base64,
  )
) {
  throw new Error("FMD reference is not the qualified single-assignment repair");
}
const marker = baselineFiles.get(manifest.markerAsset);
if (!marker || digest(Buffer.from(marker.base64, "base64")) !== manifest.markerAssetSha256) {
  throw new Error("FMD marker asset differs from its qualified source");
}
const safeWrapper =
  'const providerText = document.createElement("span");\n' +
  '    providerText.style.display = "inline-block";\n' +
  '    providerText.style.clipPath = "inset(0)";\n' +
  "    providerText.textContent = loc.provider;\n" +
  '    document.getElementById("providerView").replaceChildren(providerText);';
const detailsSource = original.replace(manifest.unsafeAssignment, safeWrapper);
const detailsFiles = baseline.files.map((file) =>
  file.name === manifest.entry
    ? { ...file, base64: Buffer.from(detailsSource).toString("base64") }
    : file,
);
const id = digest(manifest);
const installationId = randomBytes(12).toString("hex");
const parent = `/opt/sitecmd-benchmark/fmd-runtimes/${id}`;
const directory = `${parent}/${installationId}`;
mkdirSync(parent, { recursive: true, mode: 0o755 });
mkdirSync(directory, { mode: 0o755 });
try {
  materializeRepositoryFiles(baseline.files, path.join(directory, "baseline"));
  materializeRepositoryFiles(reference.files, path.join(directory, "reference"));
  materializeRepositoryFiles(detailsFiles, path.join(directory, "details-reference"));
  const installation = {
    schemaVersion: 1,
    id,
    installationId,
    directory,
    baselineSha256: baseline.sha256,
    referenceSha256,
    detailsSourceSha256: digest(Buffer.from(detailsSource)),
    createdAt: new Date().toISOString(),
  };
  writeFileSync(path.join(directory, "receipt.json"), JSON.stringify(installation), {
    flag: "wx",
    mode: 0o644,
  });
  const lock = { ...installation, treeSha256: fmdReferenceTreeDigest(directory) };
  const referenceRuntime = { ...lock, sha256: digest(lock) };
  const runtime = {
    schemaVersion: 1,
    kind: "fmd-browser-v1",
    browser: captureBrowserRuntime(),
    reference: referenceRuntime,
  };
  console.log(JSON.stringify(verifyFmdBrowserRuntime(runtime)));
} catch (error) {
  writeFileSync(path.join(directory, "failure.json"), JSON.stringify({ error: error.message }), {
    flag: "wx",
    mode: 0o600,
  });
  throw error;
}
