import { validateRepositoryFiles, validateRepositorySnapshot } from "./repository-snapshot.mjs";
import { digest } from "./workflow-plan.mjs";

const HASH = /^[a-f0-9]{64}$/;

function safeRelativePath(value) {
  return (
    typeof value === "string" &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    value.split("/").every((part) => part && part !== "." && part !== "..")
  );
}

export function validateRepositoryReference(reference) {
  const { sha256, ...content } = reference ?? {};
  if (
    reference?.schemaVersion !== 1 ||
    !["implementation-only", "implementation-regions"].includes(reference.kind) ||
    !HASH.test(reference.baselineSha256 ?? "") ||
    !HASH.test(reference.upstreamSha256 ?? "") ||
    !Array.isArray(reference.editableFiles) ||
    !reference.editableFiles.length ||
    new Set(reference.editableFiles).size !== reference.editableFiles.length ||
    !reference.editableFiles.every(safeRelativePath) ||
    !HASH.test(sha256 ?? "") ||
    sha256 !== digest(content)
  ) {
    throw new Error("Invalid repository reference identity");
  }
  validateRepositoryFiles(reference.files);
  if (reference.kind === "implementation-only") {
    if (reference.regions !== undefined)
      throw new Error("Implementation-only references cannot contain regions");
  } else if (
    !Array.isArray(reference.regions) ||
    !reference.regions.length ||
    reference.regions.some(
      (region) =>
        !reference.editableFiles.includes(region?.file) ||
        typeof region.start !== "string" ||
        !region.start ||
        typeof region.end !== "string" ||
        !region.end ||
        region.start === region.end,
    ) ||
    reference.editableFiles.some(
      (name) => !reference.regions.some((region) => region.file === name),
    )
  ) {
    throw new Error("Invalid repository reference regions");
  }
  return reference;
}

function markerPosition(text, marker, label) {
  const position = text.indexOf(marker);
  if (position < 0 || text.indexOf(marker, position + 1) >= 0)
    throw new Error(`Reference region ${label} marker must occur exactly once`);
  return position;
}

function copyRegions(original, upstream, regions) {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let output = decoder.decode(Buffer.from(original.base64, "base64"));
  const source = decoder.decode(Buffer.from(upstream.base64, "base64"));
  for (const region of regions) {
    const outputStart = markerPosition(output, region.start, "start");
    const outputEnd = markerPosition(output, region.end, "end");
    const sourceStart = markerPosition(source, region.start, "start");
    const sourceEnd = markerPosition(source, region.end, "end");
    if (outputEnd <= outputStart || sourceEnd <= sourceStart)
      throw new Error("Reference region end marker must follow its start marker");
    output =
      output.slice(0, outputStart) + source.slice(sourceStart, sourceEnd) + output.slice(outputEnd);
  }
  return { ...original, base64: Buffer.from(output).toString("base64") };
}

export function deriveRepositoryReference(baseline, upstream, editableFiles, regions) {
  validateRepositorySnapshot(baseline);
  validateRepositorySnapshot(upstream);
  const replacements = new Map(upstream.files.map((file) => [file.name, file]));
  const originals = new Map(baseline.files.map((file) => [file.name, file]));
  if (
    !Array.isArray(editableFiles) ||
    !editableFiles.length ||
    new Set(editableFiles).size !== editableFiles.length ||
    editableFiles.some((name) => !originals.has(name) || !replacements.has(name))
  )
    throw new Error("Reference edit scope must name distinct existing files in both sources");
  for (const name of editableFiles)
    if (originals.get(name).mode !== replacements.get(name).mode)
      throw new Error(`Reference changes an executable mode: ${name}`);
  if (regions !== undefined) {
    if (
      !Array.isArray(regions) ||
      !regions.length ||
      regions.some(
        (region) =>
          !region ||
          !editableFiles.includes(region.file) ||
          typeof region.start !== "string" ||
          !region.start ||
          typeof region.end !== "string" ||
          !region.end ||
          region.start === region.end,
      ) ||
      editableFiles.some((name) => !regions.some((region) => region.file === name))
    )
      throw new Error("Reference regions must cover each editable file with distinct markers");
  }
  const selected = regions
    ? new Map(
        editableFiles.map((name) => [
          name,
          copyRegions(
            originals.get(name),
            replacements.get(name),
            regions.filter((region) => region.file === name),
          ),
        ]),
      )
    : replacements;
  const content = {
    schemaVersion: 1,
    kind: regions ? "implementation-regions" : "implementation-only",
    baselineSha256: baseline.sha256,
    upstreamSha256: upstream.sha256,
    editableFiles,
    ...(regions ? { regions } : {}),
    files: baseline.files.map((file) =>
      editableFiles.includes(file.name) ? selected.get(file.name) : file,
    ),
  };
  return validateRepositoryReference({ ...content, sha256: digest(content) });
}
