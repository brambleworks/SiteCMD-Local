import { digest } from "../lib/workflow-plan.mjs";
import { executeCandidate } from "./candidate-sandbox.mjs";
import { gradeTornado } from "./tornado-grader.mjs";
import { gradeLinkding } from "./linkding-grader.mjs";
import { probeLinkdingBrowser } from "./linkding-browser-grader.mjs";
import { gradeWhoogle } from "./whoogle-grader.mjs";
import { gradeFlaskReuploaded } from "./flask-reuploaded-grader.mjs";
import { gradeConfirmatoryRepository } from "./confirmatory-grader.mjs";
import { gradeReplacementRepository, isReplacementCase } from "./replacement-grader.mjs";
import { gradeOnekeyRepository, onekeyCaseId } from "./replacement-onekey-grader.mjs";
import { fmdCaseId, gradeFmdRepository } from "./replacement-fmd-grader.mjs";
import { gradeReplacementControlRepository } from "./replacement-control-grader.mjs";
import { isReplacementControlCase } from "./replacement-control-cases.mjs";

export function gradeRepository(item, candidate, execute = executeCandidate) {
  if (item.id === fmdCaseId) return gradeFmdRepository(item, candidate, execute);
  if (item.id === onekeyCaseId) return gradeOnekeyRepository(item, candidate, execute);
  if (isReplacementControlCase(item.id)) {
    return gradeReplacementControlRepository(item, candidate, execute);
  }
  if (isReplacementCase(item.id)) return gradeReplacementRepository(item, candidate, execute);
  if (item.id === "tornado-static-redirect") return gradeTornado(candidate, execute);
  if (item.id === "whoogle-named-config-path") {
    return {
      ...gradeWhoogle(candidate, execute, item.repositoryRuntime),
      runtimeSha256: digest(item.repositoryRuntime),
    };
  }
  if (item.repository === "flask-reuploaded") {
    return {
      ...gradeFlaskReuploaded(item.id, candidate, execute, item.repositoryRuntime),
      runtimeSha256: digest(item.repositoryRuntime),
    };
  }
  if (item.confirmatory === true) return gradeConfirmatoryRepository(item, candidate, execute);
  if (item.id !== "linkding-asset-sandbox") throw new Error("Unsupported repository grader");
  const django = gradeLinkding(candidate, execute, item.repositoryRuntime);
  const browser = probeLinkdingBrowser(
    candidate,
    item.repositoryRuntime,
    item.browserRuntime,
    execute,
  );
  return {
    ...django,
    browser,
    runtimeSha256: digest(item.repositoryRuntime),
    browserRuntimeSha256: digest(item.browserRuntime),
    acceptancePass: django.acceptancePass && browser.acceptancePass,
    regressionsPass: django.regressionsPass && browser.regressionsPass,
  };
}
