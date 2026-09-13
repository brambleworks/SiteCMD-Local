import assert from "node:assert/strict";
import { test } from "node:test";
import { replacementCaseDefinition, replacementCaseIds } from "../guest/replacement-cases.mjs";
import {
  gradeReplacementRepository,
  normalizeReplacementGrade,
} from "../guest/replacement-grader.mjs";
import { gradeRepository } from "../guest/repository-grader.mjs";

const { validateReplacementPath, validateReplacementRequest } =
  await import("../guest/replacement-node-candidate.mjs");

const expectedCases = {
  "alist-ldap-tls-verification": [
    "tls",
    ["internal/conf/config.go", "server/handles/ldap_login.go"],
  ],
  "alps-message-reader-inert-parsing": [
    "unsafe-html",
    ["frontend/src/components/message-reader.ts", "frontend/src/utils/reader-utils.ts"],
  ],
  "bigflow-deploy-tls-verification": ["tls", ["bigflow/deploy.py"]],
  "blackduck-client-tls-verification": ["tls", ["blackduck/HubRestApi.py"]],
  "css-parser-http-tls-verification": ["tls", ["lib/css_parser/parser.rb"]],
  "django-grappelli-switch-redirect": ["redirect", ["grappelli/views/switch.py"]],
  "formwork-tag-label-text": ["unsafe-html", ["panel/src/ts/components/inputs/tags-input.ts"]],
  "formwork-update-status-text": ["unsafe-html", ["panel/src/ts/components/views/updates.ts"]],
  "gobot-mqtt-tls-verification": ["tls", ["platforms/mqtt/mqtt_adaptor.go"]],
  "graphql-tools-websocket-tls-verification": [
    "tls",
    ["packages/executors/legacy-ws/src/index.ts"],
  ],
  "kaarya-postgres-tls-verification": ["tls", ["server/src/db-pg.js"]],
  "kubex-postgres-tls-verification": ["tls", ["services/mcp-server/src/clients/postgres.ts"]],
  "libmongocrypt-kms-tls-verification": ["tls", ["bindings/node/lib/stateMachine.js"]],
  "liljs-element-text-rendering": ["unsafe-html", ["src/liljs.js"]],
  "mnml-search-result-text-rendering": ["unsafe-html", ["static/js/search.js"]],
  "nbdime-diff-response-text": ["unsafe-html", ["packages/webapp/src/app/diff.ts"]],
  "nbdime-merge-response-text": ["unsafe-html", ["packages/webapp/src/app/merge.ts"]],
  "node-sass-download-tls-verification": ["tls", ["scripts/util/downloadoptions.js"]],
  "oobee-updater-tls-verification": ["tls", ["public/electron/main.js"]],
  "streetlives-rds-tls-verification": ["tls", ["src/config.js"]],
  "warewoolf-chapter-title-rendering": ["unsafe-html", ["src/render.js"]],
  "xteve-log-entry-rendering": ["unsafe-html", ["ts/logs_ts.ts"]],
};

test("replacement case manifest pins every qualified generic repair scope", () => {
  assert.deepEqual(replacementCaseIds, Object.keys(expectedCases));
  for (const [caseId, [family, files]] of Object.entries(expectedCases)) {
    assert.deepEqual(replacementCaseDefinition(caseId), { family, files });
  }
  assert.throws(() => replacementCaseDefinition("unknown"), /Unsupported replacement grader/);
});

test("replacement adapter rejects paths and scopes outside the manifest", () => {
  for (const file of [
    "/etc/passwd",
    "../secret",
    "source/../secret",
    "source\\secret",
    "source//secret",
    "./source",
    "source\0secret",
  ]) {
    assert.throws(() => validateReplacementPath(file), /unsafe source path/);
  }
  const definition = replacementCaseDefinition("bigflow-deploy-tls-verification");
  assert.deepEqual(
    validateReplacementRequest({
      operation: "bigflow-deploy-tls-verification",
      files: definition.files,
    }),
    { caseId: "bigflow-deploy-tls-verification", ...definition },
  );
  assert.throws(
    () =>
      validateReplacementRequest({
        operation: "bigflow-deploy-tls-verification",
        files: ["bigflow/deploy.py", "README.md"],
      }),
    /do not match/,
  );
});

test("replacement repository grading forces the isolated adapter and validates evidence", () => {
  const item = { id: "bigflow-deploy-tls-verification", runtime: "python" };
  const valid = {
    observed: { secureDefault: true },
    acceptance: [{ name: "Secure", actual: true, pass: true }],
    regressions: [{ name: "Compatible", actual: true, pass: true }],
    acceptancePass: true,
    regressionsPass: true,
  };
  const execute = (context, candidate, input) => {
    assert.equal(context.replacementAdapter, true);
    assert.equal(context.runtime, "python");
    assert.equal(candidate, "/candidate");
    assert.deepEqual(input, {
      operation: item.id,
      files: ["bigflow/deploy.py"],
    });
    return valid;
  };
  assert.deepEqual(gradeReplacementRepository(item, "/candidate", execute), valid);
  assert.deepEqual(gradeRepository(item, "/candidate", execute), valid);
});

test("replacement repository grading fails closed on malformed adapter output", () => {
  for (const malformed of [
    null,
    { error: "CandidateProcessError", message: "blocked" },
    {
      acceptance: [],
      regressions: [],
      acceptancePass: true,
      regressionsPass: true,
    },
    {
      acceptance: [{ name: "Secure", pass: false }],
      regressions: [{ name: "Compatible", pass: true }],
      acceptancePass: true,
      regressionsPass: true,
    },
  ]) {
    const result = normalizeReplacementGrade(malformed);
    assert.equal(result.acceptancePass, false);
    assert.equal(result.regressionsPass, false);
    assert.match(result.probeError, /.+/);
  }
});
