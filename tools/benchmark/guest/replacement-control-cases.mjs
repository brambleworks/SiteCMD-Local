const definitions = Object.freeze({
  "control-dompurify-sanitizer-internal": {
    sourceSha256: "0af7cb4fa864af5bbb26d62064df394da7a2c671518dc70935e98d384bde4335",
    targetPath: "site/assets/scripts/dompurify.js",
    targetSha256: "c7db7a6239a64f5dd64bf8f5391188944f9b288897bd57b6d3ced6965bcdc232",
    treeSha256: "e2b36c9d25d42d8820af43ab899e2f8301f7d4604660bbf41d79e6104453596e",
    fileCount: 115,
    bytes: 1175224,
  },
  "control-emoji-category-escaped-html": {
    sourceSha256: "9b905d79331f327654d0e8214d3bacf7f02ed3475cd6fe252adce99476e30ecf",
    targetPath: "src/emojiArea.ts",
    targetSha256: "d4c55b63477282a7b6447226a1a81ec756c3b1eff5e9241053c75c8089e667ee",
    treeSha256: "6ea1ebdb2acea756dcf9e79df468f474fb9b7a0074ad3bebc30ce31a2ccd10a9",
    fileCount: 120,
    bytes: 3381927,
  },
  "control-emoji-preview-name-escaped-html": {
    sourceSha256: "9b905d79331f327654d0e8214d3bacf7f02ed3475cd6fe252adce99476e30ecf",
    targetPath: "src/preview.ts",
    targetSha256: "166acdb90a0d6da32d15e838cc5d14a5851a5126aa267fd5d0d056290ba49a31",
    treeSha256: "6ea1ebdb2acea756dcf9e79df468f474fb9b7a0074ad3bebc30ce31a2ccd10a9",
    fileCount: 120,
    bytes: 3381927,
  },
  "control-hippietv-static-shadow-shell": {
    sourceSha256: "9721c60aec1ef74b27fe9c524ca0c5d5f10a92cfae3dcf6c685ffe9d148bbc32",
    targetPath: "www/hippietv-remote-card.js",
    targetSha256: "854129cacd2b68d9454e32a75a50028e587795682921e92ab7419c1bfe7315cf",
    treeSha256: "04e393c1ffbd7f59ae53e5b53620fcd29be8e013a0e590f4d36ec105be1d9fcd",
    fileCount: 16,
    bytes: 104462,
  },
  "control-memos-highlight-escaped-html": {
    sourceSha256: "9706bbb073e3d4310de6d9160acdacac6fc3b9f364361ae370d912ed00268902",
    targetPath: "web/src/labs/highlighter/index.ts",
    targetSha256: "e40ae573a85de9e5e051fb91995cd7be89b76e7d2c8b1b7cda4e86d490a8bdeb",
    treeSha256: "c6fdc951ea30326953cbcca171458321bbf2dd2ce6ac9e6cd033a968ab9f96a9",
    fileCount: 311,
    bytes: 1541218,
  },
  "control-teler-category-escaped-html": {
    sourceSha256: "66b1b6b1310a4b8a8f105fc97ea6dafe1f352ae2bc6810cc3569aaa44554e125",
    targetPath: "internal/event/www/script.js",
    targetSha256: "20b9d6b9fe630a5e08ad1baa24cbc52b4ec398218f4dc5d229ab43fa6192da61",
    treeSha256: "66d081d99985384ab15bf1d5d6ee9d046c672b67051fa5b13d65f54b349f1d7d",
    fileCount: 86,
    bytes: 200463,
  },
  "control-token-optimizer-instructional-rule-text": {
    sourceSha256: "a16f89e4b16de1b195da40a05a2f9d9b6733c264ec7b3ac0d60e2d2d0b977109",
    targetPath: "src/tools/code-analysis/smart-security.ts",
    targetSha256: "8afdb9ea49f7587051b83c7da22e20e58e2403ad994f00b9738ea93e8cb91563",
    treeSha256: "ca9dab73e0b190073cc040c576c952febe3b0ce3f390d318df6849572b491d48",
    fileCount: 301,
    bytes: 4428664,
  },
  "control-xteve-empty-dom-clear": {
    sourceSha256: "3da9d8d9fcbbb8cc5ab6f3afb72e2c714337d35a6903a1fd78b30fbb5eab1326",
    targetPath: "ts/logs_ts.ts",
    targetSha256: "bd0ec746d8a90ceaa8a6c38b9cc49c9993d2830a9eaa41ecfae0f7de73c0f731",
    treeSha256: "18898fb56ed8c2373f951ae547d41f239500de6e2910b9ab1b4bd4405fe8182a",
    fileCount: 108,
    bytes: 6287831,
  },
});

export const replacementControlCaseIds = Object.freeze(Object.keys(definitions));

for (const [id, definition] of Object.entries(definitions)) {
  if (
    !id.startsWith("control-") ||
    ![definition.sourceSha256, definition.targetSha256, definition.treeSha256].every((value) =>
      /^[a-f0-9]{64}$/.test(value),
    ) ||
    definition.targetPath.startsWith("/") ||
    definition.targetPath.split("/").some((part) => !part || part === "." || part === "..") ||
    !Number.isSafeInteger(definition.fileCount) ||
    definition.fileCount < 1 ||
    !Number.isSafeInteger(definition.bytes) ||
    definition.bytes < 1
  ) {
    throw new Error(`Invalid replacement control definition: ${id}`);
  }
}

export function isReplacementControlCase(caseId) {
  return Object.hasOwn(definitions, caseId);
}

export function replacementControlDefinition(caseId) {
  const definition = definitions[caseId];
  if (!definition) throw new Error(`Unsupported replacement control: ${caseId}`);
  return structuredClone(definition);
}
