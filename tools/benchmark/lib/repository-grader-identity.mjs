import { digest } from "./workflow-plan.mjs";
import { replacementCaseIds } from "../guest/replacement-cases.mjs";
import { replacementControlCaseIds } from "../guest/replacement-control-cases.mjs";

const commonFiles = [
  "guest/browser-inputs.mjs",
  "guest/browser-runtime.mjs",
  "guest/candidate-sandbox.mjs",
  "guest/desktop-session.mjs",
  "guest/flask-reuploaded-grader.mjs",
  "guest/flask-reuploaded-runtime.mjs",
  "guest/linkding-browser-grader.mjs",
  "guest/linkding-grader.mjs",
  "guest/linkding-runtime.mjs",
  "guest/confirmatory-grader.mjs",
  "guest/confirmatory-dom.mjs",
  "guest/replacement-cases.mjs",
  "guest/replacement-control-cases.mjs",
  "guest/replacement-control-grader.mjs",
  "guest/replacement-fmd-executor.mjs",
  "guest/replacement-fmd-grader.mjs",
  "guest/replacement-grader.mjs",
  "guest/replacement-onekey-grader.mjs",
  "guest/replacement-onekey-runtime.mjs",
  "guest/repository-grader.mjs",
  "guest/tornado-grader.mjs",
  "guest/whoogle-grader.mjs",
  "guest/whoogle-runtime.mjs",
  "lib/repository-runtime.mjs",
  "lib/workflow-contract.mjs",
  "lib/workflow-plan.mjs",
];

const replacementFiles = [
  "guest/replacement-dom.mjs",
  "guest/replacement-node-candidate.mjs",
  "guest/replacement-redirect-python.py",
  "guest/replacement-redirect.mjs",
  "guest/replacement-tls-python.py",
  "guest/replacement-tls.mjs",
  "guest/replacement-unsafe-html.mjs",
  "vendor/typescript.cjs",
];

const caseFiles = {
  "fmd-device-text": [
    "cases/fmd-runtime.json",
    "guest/replacement-fmd-actions.js",
    "guest/replacement-fmd-controller.mjs",
    "guest/replacement-fmd-fixture.mjs",
    "guest/replacement-fmd-path.mjs",
    "guest/replacement-fmd-probe.py",
    "guest/replacement-fmd-reference.mjs",
    "guest/replacement-fmd-runtime.mjs",
  ],
  "onekey-http-client-tls-verification": [
    "cases/onekey-runtime.json",
    "guest/replacement-onekey-candidate.py",
    "guest/replacement-onekey-fixtures.py",
    "guest/replacement-onekey-probe.py",
  ],
  "tornado-static-redirect": ["guest/tornado-candidate.py"],
  "linkding-asset-sandbox": [
    "cases/linkding-calibration.json",
    "guest/linkding-browser.py",
    "guest/linkding-candidate.py",
    "guest/webdriver-session.py",
  ],
  "whoogle-named-config-path": ["cases/whoogle-calibration.json", "guest/whoogle-candidate.py"],
  "claude-code-templates-shell-boundary": [
    "guest/confirmatory-node-candidate.mjs",
    "vendor/typescript.cjs",
  ],
  "material-search-suggestion-text": [
    "guest/confirmatory-node-candidate.mjs",
    "vendor/typescript.cjs",
  ],
  "lightrag-wildcard-cors-credentials": ["guest/confirmatory-python-candidate.py"],
  "glances-configurable-cors-credentials": ["guest/confirmatory-python-candidate.py"],
  "sagemaker-triton-tls-verification": ["guest/confirmatory-python-candidate.py"],
  "yamcs-extension-element-construction": [
    "guest/confirmatory-node-candidate.mjs",
    "vendor/typescript.cjs",
  ],
  "claude-code-templates-loopback-control": [
    "guest/confirmatory-node-candidate.mjs",
    "vendor/typescript.cjs",
  ],
  "liveatlas-entity-decoder-control": [
    "guest/confirmatory-node-candidate.mjs",
    "vendor/typescript.cjs",
  ],
  ...Object.fromEntries(replacementCaseIds.map((caseId) => [caseId, replacementFiles])),
  ...Object.fromEntries(
    replacementControlCaseIds.map((caseId) => [
      caseId,
      ["guest/replacement-control-candidate.mjs", "guest/replacement-control-hash.mjs"],
    ]),
  ),
};

export function repositoryGraderFiles(caseId) {
  const selected = caseFiles[caseId];
  if (!selected) throw new Error(`Unsupported repository grader: ${caseId}`);
  return [...commonFiles, ...selected].sort();
}

export function repositoryGraderIdentity(files, caseId) {
  const selected = Object.fromEntries(
    repositoryGraderFiles(caseId).map((name) => {
      if (typeof files[name] !== "string") throw new Error(`Missing grader file: ${name}`);
      return [name, files[name]];
    }),
  );
  return digest(selected);
}
