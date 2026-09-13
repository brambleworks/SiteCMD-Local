import {
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  openSync,
  readFileSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { controlFileSha256, controlTreeEvidence } from "./replacement-control-hash.mjs";

function inspectCandidate(targetPath) {
  const entries = [];
  let filesystemEntries = 0;
  let bytes = 0;
  let targetSha256 = null;

  function visit(relative) {
    const directory = path.join("/work", relative);
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((left, right) =>
      left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
    )) {
      const name = relative ? `${relative}/${entry.name}` : entry.name;
      const candidate = path.join("/work", name);
      if (++filesystemEntries > 5_000) throw new Error("Control candidate has too many entries");
      if (entry.isSymbolicLink()) throw new Error(`Control candidate contains a link: ${name}`);
      if (entry.isDirectory()) {
        visit(name);
        continue;
      }
      if (!entry.isFile() || entries.length >= 1_000) {
        throw new Error(`Control candidate contains an unsupported entry: ${name}`);
      }
      const before = lstatSync(candidate);
      // codeql-allow: js/file-system-race
      const handle = openSync(
        candidate,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      try {
        const opened = fstatSync(handle);
        if (
          !opened.isFile() ||
          opened.nlink !== 1 ||
          opened.ino !== before.ino ||
          opened.dev !== before.dev
        ) {
          throw new Error(`Control candidate changed during inspection: ${name}`);
        }
        bytes += opened.size;
        if (opened.size > 4 * 1024 * 1024 || bytes > 16 * 1024 * 1024) {
          throw new Error("Control candidate exceeds its byte limit");
        }
        const contents = readFileSync(handle);
        const mode = opened.mode & 0o111 ? "100755" : "100644";
        entries.push({ name, mode, contents });
        if (name === targetPath) targetSha256 = controlFileSha256(contents);
      } finally {
        closeSync(handle);
      }
    }
  }

  visit("");
  return {
    isolation: { uid: process.getuid(), candidateSuppliesVerdict: false },
    targetSha256,
    ...controlTreeEvidence(entries),
  };
}

try {
  const request = JSON.parse(readFileSync(0, "utf8"));
  if (
    typeof request.targetPath !== "string" ||
    request.targetPath.startsWith("/") ||
    request.targetPath.split("/").some((part) => !part || part === "." || part === "..")
  ) {
    throw new Error("Control target path is invalid");
  }
  console.log(JSON.stringify(inspectCandidate(request.targetPath)));
} catch (error) {
  console.log(
    JSON.stringify({
      error: "ControlInspectionError",
      message: error instanceof Error ? error.message : String(error),
    }),
  );
}
