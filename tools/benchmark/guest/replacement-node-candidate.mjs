import { closeSync, constants, fstatSync, openSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { replacementCaseDefinition } from "./replacement-cases.mjs";
import { gradeRedirectCandidate } from "./replacement-redirect.mjs";
import { gradeTlsCandidate } from "./replacement-tls.mjs";
import { gradeUnsafeHtmlCandidate } from "./replacement-unsafe-html.mjs";

const workDirectory = "/work";
const maximumSourceBytes = 4 * 1024 * 1024;

export function validateReplacementPath(file) {
  if (
    typeof file !== "string" ||
    file.length === 0 ||
    file.includes("\\") ||
    file.includes("\0") ||
    path.posix.isAbsolute(file)
  ) {
    throw new Error("Replacement grader received an unsafe source path");
  }
  const segments = file.split("/");
  if (segments.some((segment) => segment.length === 0 || segment === "." || segment === "..")) {
    throw new Error("Replacement grader received an unsafe source path");
  }
  return file;
}

export function validateReplacementRequest(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("Replacement grader input must be an object");
  }
  const definition = replacementCaseDefinition(input.operation);
  if (!Array.isArray(input.files)) {
    throw new Error("Replacement grader source paths must be an array");
  }
  const requested = input.files.map(validateReplacementPath);
  if (
    requested.length !== definition.files.length ||
    requested.some((file, index) => file !== definition.files[index])
  ) {
    throw new Error(`Replacement grader source paths do not match ${input.operation}`);
  }
  return { caseId: input.operation, ...definition };
}

function readCaseFiles(files) {
  return Object.fromEntries(
    files.map((file) => {
      const requested = path.resolve(workDirectory, file);
      if (!requested.startsWith(`${workDirectory}/`)) {
        throw new Error("Replacement grader source path escaped the candidate repository");
      }
      const resolved = realpathSync(requested);
      if (!resolved.startsWith(`${workDirectory}/`)) {
        throw new Error("Replacement grader source symlink escaped the candidate repository");
      }
      const handle = openSync(
        resolved,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
      );
      try {
        const metadata = fstatSync(handle);
        if (!metadata.isFile() || metadata.size > maximumSourceBytes) {
          throw new Error("Replacement grader source is not a supported regular file");
        }
        return [file, readFileSync(handle, "utf8")];
      } finally {
        closeSync(handle);
      }
    }),
  );
}

export async function runReplacementCandidate(input) {
  const definition = validateReplacementRequest(input);
  const files = readCaseFiles(definition.files);
  if (definition.family === "tls") {
    return gradeTlsCandidate(definition.caseId, files);
  }
  if (definition.family === "unsafe-html") {
    return gradeUnsafeHtmlCandidate(definition.caseId, files);
  }
  if (definition.family === "redirect") {
    return gradeRedirectCandidate(files);
  }
  throw new Error(`Unsupported replacement grader family: ${definition.family}`);
}

async function main() {
  try {
    const input = JSON.parse(readFileSync(0, "utf8"));
    process.stdout.write(JSON.stringify(await runReplacementCandidate(input)));
  } catch (error) {
    process.stdout.write(
      JSON.stringify({
        error: "ReplacementAdapterError",
        message: error instanceof Error ? error.message : String(error),
      }),
    );
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await main();
}
