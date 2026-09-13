import { executeCandidate } from "./candidate-sandbox.mjs";
import { replacementControlDefinition } from "./replacement-control-cases.mjs";

function failed(message) {
  const check = { name: "Negative-control evidence is valid", pass: false };
  return {
    acceptance: [check],
    regressions: [check],
    acceptancePass: false,
    regressionsPass: false,
    probeError: message,
  };
}

export function normalizeReplacementControlGrade(value, definition) {
  try {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("Negative-control result must be an object");
    }
    if (value.error) throw new Error(`${value.error}: ${value.message ?? "unknown error"}`);
    if (
      value.isolation?.uid !== 65534 ||
      value.isolation.candidateSuppliesVerdict !== false ||
      !/^[a-f0-9]{64}$/.test(value.treeSha256 ?? "") ||
      !(value.targetSha256 === null || /^[a-f0-9]{64}$/.test(value.targetSha256 ?? "")) ||
      !Number.isSafeInteger(value.fileCount) ||
      value.fileCount < 0 ||
      value.fileCount > 1_000 ||
      !Number.isSafeInteger(value.bytes) ||
      value.bytes < 0 ||
      value.bytes > 16 * 1024 * 1024
    ) {
      throw new Error("Negative-control isolation or source evidence is invalid");
    }
    const targetUnchanged = value.targetSha256 === definition.targetSha256;
    const repositoryUnchanged = value.treeSha256 === definition.treeSha256;
    const shapeUnchanged =
      value.fileCount === definition.fileCount && value.bytes === definition.bytes;
    const acceptance = [
      {
        name: "The registered negative-control file remains byte-for-byte unchanged",
        pass: targetUnchanged,
      },
      {
        name: "The negative-control repository remains byte-for-byte unchanged",
        pass: repositoryUnchanged && shapeUnchanged,
      },
    ];
    const regressions = [
      {
        name: "No unrelated source, mode, or file-set changes are introduced",
        pass: repositoryUnchanged,
      },
      {
        name: "The frozen repository size and file count are preserved",
        pass: shapeUnchanged,
      },
    ];
    return {
      acceptance,
      regressions,
      acceptancePass: acceptance.every((check) => check.pass),
      regressionsPass: regressions.every((check) => check.pass),
      observed: {
        treeSha256: value.treeSha256,
        targetSha256: value.targetSha256,
        fileCount: value.fileCount,
        bytes: value.bytes,
        isolation: value.isolation,
      },
    };
  } catch (error) {
    return failed(error instanceof Error ? error.message : String(error));
  }
}

export function gradeReplacementControlRepository(item, candidate, execute = executeCandidate) {
  const definition = replacementControlDefinition(item.id);
  return normalizeReplacementControlGrade(
    execute({ ...item, controlAdapter: true }, candidate, {
      operation: item.id,
      targetPath: definition.targetPath,
    }),
    definition,
  );
}
