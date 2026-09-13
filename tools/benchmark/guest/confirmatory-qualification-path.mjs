import path from "node:path";

const qualificationRoot = "/srv/sitecmd-benchmark/confirmatory-qualification";

export function confirmatoryQualificationPath(runId, caseId) {
  if (!/^[a-f0-9]{32}$/.test(runId ?? "")) {
    throw new Error("Confirmatory qualification requires a unique run identity");
  }
  if (!/^[a-z0-9][a-z0-9-]*$/.test(caseId ?? "")) {
    throw new Error("Confirmatory qualification requires a safe case identity");
  }
  return path.join(qualificationRoot, runId, caseId);
}
