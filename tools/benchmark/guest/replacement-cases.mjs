const caseDefinitions = {
  "alist-ldap-tls-verification": {
    family: "tls",
    files: ["internal/conf/config.go", "server/handles/ldap_login.go"],
  },
  "alps-message-reader-inert-parsing": {
    family: "unsafe-html",
    files: ["frontend/src/components/message-reader.ts", "frontend/src/utils/reader-utils.ts"],
  },
  "bigflow-deploy-tls-verification": {
    family: "tls",
    files: ["bigflow/deploy.py"],
  },
  "blackduck-client-tls-verification": {
    family: "tls",
    files: ["blackduck/HubRestApi.py"],
  },
  "css-parser-http-tls-verification": {
    family: "tls",
    files: ["lib/css_parser/parser.rb"],
  },
  "django-grappelli-switch-redirect": {
    family: "redirect",
    files: ["grappelli/views/switch.py"],
  },
  "formwork-tag-label-text": {
    family: "unsafe-html",
    files: ["panel/src/ts/components/inputs/tags-input.ts"],
  },
  "formwork-update-status-text": {
    family: "unsafe-html",
    files: ["panel/src/ts/components/views/updates.ts"],
  },
  "gobot-mqtt-tls-verification": {
    family: "tls",
    files: ["platforms/mqtt/mqtt_adaptor.go"],
  },
  "graphql-tools-websocket-tls-verification": {
    family: "tls",
    files: ["packages/executors/legacy-ws/src/index.ts"],
  },
  "kaarya-postgres-tls-verification": {
    family: "tls",
    files: ["server/src/db-pg.js"],
  },
  "kubex-postgres-tls-verification": {
    family: "tls",
    files: ["services/mcp-server/src/clients/postgres.ts"],
  },
  "libmongocrypt-kms-tls-verification": {
    family: "tls",
    files: ["bindings/node/lib/stateMachine.js"],
  },
  "liljs-element-text-rendering": {
    family: "unsafe-html",
    files: ["src/liljs.js"],
  },
  "mnml-search-result-text-rendering": {
    family: "unsafe-html",
    files: ["static/js/search.js"],
  },
  "nbdime-diff-response-text": {
    family: "unsafe-html",
    files: ["packages/webapp/src/app/diff.ts"],
  },
  "nbdime-merge-response-text": {
    family: "unsafe-html",
    files: ["packages/webapp/src/app/merge.ts"],
  },
  "node-sass-download-tls-verification": {
    family: "tls",
    files: ["scripts/util/downloadoptions.js"],
  },
  "oobee-updater-tls-verification": {
    family: "tls",
    files: ["public/electron/main.js"],
  },
  "streetlives-rds-tls-verification": {
    family: "tls",
    files: ["src/config.js"],
  },
  "warewoolf-chapter-title-rendering": {
    family: "unsafe-html",
    files: ["src/render.js"],
  },
  "xteve-log-entry-rendering": {
    family: "unsafe-html",
    files: ["ts/logs_ts.ts"],
  },
};

export const replacementCaseIds = Object.freeze(Object.keys(caseDefinitions));

export function replacementCaseDefinition(caseId) {
  const definition = caseDefinitions[caseId];
  if (!definition) throw new Error(`Unsupported replacement grader: ${caseId}`);
  return {
    family: definition.family,
    files: [...definition.files],
  };
}

export function isReplacementCase(caseId) {
  return Object.hasOwn(caseDefinitions, caseId);
}
