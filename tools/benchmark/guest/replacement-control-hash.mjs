import { createHash } from "node:crypto";

export function controlFileSha256(contents) {
  return createHash("sha256").update(contents).digest("hex");
}

export function controlTreeEvidence(entries) {
  const files = [...entries]
    .map(({ name, mode, contents }) => ({
      name,
      mode,
      bytes: contents.length,
      sha256: controlFileSha256(contents),
    }))
    .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  return {
    treeSha256: controlFileSha256(Buffer.from(JSON.stringify(files))),
    fileCount: files.length,
    bytes: files.reduce((total, file) => total + file.bytes, 0),
  };
}
