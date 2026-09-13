import { createRequire } from "node:module";
import vm from "node:vm";
import {
  DOMParserFixture,
  DocumentFixture,
  NodeFixture,
  unsafePayload,
} from "./replacement-dom.mjs";

const hostRequire = createRequire(import.meta.url);
const ts = hostRequire(process.env.SITECMD_BENCHMARK_TYPESCRIPT ?? "typescript");

function check(name, actual) {
  return { name, actual: actual === true, pass: actual === true };
}

function result(observed, acceptance, regressions, error = null) {
  const acceptanceChecks = acceptance.map(([name, key]) => check(name, observed[key]));
  const regressionChecks = regressions.map(([name, key]) => check(name, observed[key]));
  return {
    observed,
    acceptance: acceptanceChecks,
    regressions: regressionChecks,
    acceptancePass: acceptanceChecks.every((item) => item.pass),
    regressionsPass: regressionChecks.every((item) => item.pass),
    ...(error ? { probeError: error } : {}),
  };
}

function failedResult(error) {
  return result(
    { candidateExecuted: false },
    [["Candidate executes", "candidateExecuted"]],
    [["Candidate executes", "candidateExecuted"]],
    error instanceof Error ? error.message : String(error),
  );
}

function universalStub() {
  const callable = () => universalStub();
  return new Proxy(callable, {
    get(_target, property) {
      if (property === "__esModule") return true;
      if (property === "default") return callable;
      return universalStub();
    },
    construct() {
      return {};
    },
  });
}

function compile(source, filename, moduleKind = ts.ModuleKind.CommonJS) {
  const output = ts.transpileModule(source, {
    fileName: filename,
    reportDiagnostics: true,
    compilerOptions: {
      allowJs: true,
      esModuleInterop: true,
      module: moduleKind,
      target: ts.ScriptTarget.ES2022,
    },
  });
  const errors =
    output.diagnostics?.filter(
      (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
    ) ?? [];
  if (errors.length > 0) {
    throw new Error(
      `Candidate does not parse: ${errors
        .map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, " "))
        .join("; ")}`,
    );
  }
  return output.outputText;
}

function createContext(environment = {}) {
  const context = vm.createContext({
    URL,
    URLSearchParams,
    console: { log() {}, warn() {}, error() {} },
    setTimeout,
    clearTimeout,
    queueMicrotask,
    ...environment,
  });
  context.globalThis = context;
  context.window ??= context;
  return context;
}

function loadModule(source, filename, customRequire, environment = {}) {
  const module = { exports: {} };
  const context = createContext({
    exports: module.exports,
    module,
    require: customRequire,
    __filename: `/work/${filename}`,
    __dirname: `/work/${filename}`.slice(0, `/work/${filename}`.lastIndexOf("/")),
    ...environment,
  });
  const output = compile(source, filename);
  const wrapper = new vm.Script(`(function (exports, require, module) {${output}\n})`, {
    filename: `/work/${filename}`,
  }).runInContext(context, { timeout: 3000 });
  wrapper(module.exports, customRequire, module);
  return { exports: module.exports, context };
}

function runScript(source, filename, environment = {}) {
  const context = createContext(environment);
  const output = compile(source, filename);
  new vm.Script(output, { filename: `/work/${filename}` }).runInContext(context, { timeout: 3000 });
  return context;
}

function extractFunction(source, name, filename) {
  const tree = ts.createSourceFile(filename, source, ts.ScriptTarget.Latest, true);
  let match = null;
  function visit(node) {
    if (ts.isFunctionDeclaration(node) && node.name?.text === name) match = node.getText(tree);
    if (!match) ts.forEachChild(node, visit);
  }
  visit(tree);
  if (!match) throw new Error(`Missing function ${name}`);
  return match;
}

function findAll(root, selector) {
  const matches = [];
  const data = /^\[data-([a-z-]+)=["']?([^\]"']+)["']?\]$/.exec(selector);
  function visit(node) {
    for (const child of node?.childNodes ?? []) {
      if (child.nodeType !== 1) continue;
      const key = data?.[1].replace(/-([a-z])/g, (_match, letter) => letter.toUpperCase());
      if (
        (selector.startsWith(".") && child.classList.contains(selector.slice(1))) ||
        (data && child.dataset[key] === data[2]) ||
        child.tagName.toLowerCase() === selector.toLowerCase()
      )
        matches.push(child);
      visit(child);
    }
  }
  visit(root);
  return matches;
}

class EventFixture {
  constructor(type, values = {}) {
    this.type = type;
    Object.assign(this, values);
  }

  preventDefault() {
    this.defaultPrevented = true;
  }
}

function importedHelper(mainSource) {
  const tree = ts.createSourceFile("message-reader.ts", mainSource, ts.ScriptTarget.Latest, true);
  const imports = new Map();
  const expected = new Set(["this.rawMessageHtml", "item.rawMessageHtml", "rawMessageHtml"]);
  const calls = new Map([...expected].map((value) => [value, []]));
  for (const statement of tree.statements) {
    if (
      !ts.isImportDeclaration(statement) ||
      !statement.moduleSpecifier.text.endsWith("reader-utils")
    )
      continue;
    for (const binding of statement.importClause?.namedBindings?.elements ?? []) {
      imports.set(binding.name.text, binding.propertyName?.text ?? binding.name.text);
    }
  }
  function visit(node) {
    if (
      ts.isCallExpression(node) &&
      ts.isIdentifier(node.expression) &&
      node.arguments.length === 1
    ) {
      const argument = node.arguments[0].getText(tree);
      if (calls.has(argument)) calls.get(argument).push(node.expression.text);
    }
    ts.forEachChild(node, visit);
  }
  visit(tree);
  const names = [...calls.values()].flat();
  const oneImportedHelper = names.length > 0 && new Set(names).size === 1 && imports.has(names[0]);
  const allContextsUseHelper =
    [...calls.values()].every((values) => values.length === 1) &&
    names.length === 3 &&
    oneImportedHelper;
  const allContextsConvert = [...expected].every(
    (argument) =>
      calls.get(argument).length === 1 || mainSource.includes(`innerHTML = ${argument};`),
  );
  return {
    allContextsUseHelper,
    allContextsConvert,
    importedName: oneImportedHelper ? imports.get(names[0]) : null,
  };
}

function observeAlps(files) {
  const main = files["frontend/src/components/message-reader.ts"];
  const utilities = files["frontend/src/utils/reader-utils.ts"];
  const resolution = importedHelper(main);
  if (!resolution.importedName) {
    return {
      candidateExecuted: true,
      allContextsUseHelper: false,
      noLiveMarkupActivation: false,
      markupRemoved: false,
      readableTextPreserved: resolution.allContextsConvert,
      blockBreaksPreserved: resolution.allContextsConvert,
      excludedContentRemoved: resolution.allContextsConvert,
      emptyInputPreserved: resolution.allContextsConvert,
    };
  }
  const declaration = extractFunction(utilities, resolution.importedName, "reader-utils.ts");
  const document = new DocumentFixture();
  const { exports } = loadModule(
    `${declaration}\nmodule.exports.fixtureHelper = ${resolution.importedName};`,
    "reader-utils-helper.ts",
    () => universalStub(),
    { document, DOMParser: DOMParserFixture, Node: NodeFixture },
  );
  const input =
    '<p>Hello <b>friend</b></p><script>excluded-script</script><style>excluded-style</style><div>Next<br>line</div><img src=x onerror="active()">';
  const output = exports.fixtureHelper(input);
  return {
    candidateExecuted: true,
    allContextsUseHelper: resolution.allContextsUseHelper,
    noLiveMarkupActivation: document.active === false && document.innerHTMLWrites.length === 0,
    markupRemoved: typeof output === "string" && !/<[^>]*>|onerror|javascript:/i.test(output),
    readableTextPreserved:
      resolution.allContextsConvert &&
      typeof output === "string" &&
      output.includes("Hello friend") &&
      output.includes("Next") &&
      output.includes("line"),
    blockBreaksPreserved:
      resolution.allContextsConvert &&
      typeof output === "string" &&
      /Hello friend\s*\n/.test(output) &&
      /Next\s*\nline/.test(output),
    excludedContentRemoved:
      typeof output === "string" &&
      !output.includes("excluded-script") &&
      !output.includes("excluded-style"),
    emptyInputPreserved: exports.fixtureHelper("") === "",
  };
}

function observeFormworkTags(files) {
  const document = new DocumentFixture();
  const input = document.createElement("input");
  const parent = document.createElement("div");
  parent.appendChild(input);
  input.id = "tags";
  input.name = "fixture-tags";
  input.placeholder = "Add tag";
  input.dataset.accept = "any";
  const dropdownLabel = unsafePayload("Dropdown");
  input.dataset.options = JSON.stringify({ fixture: { value: dropdownLabel, icon: "shield" } });
  const initialTagValue = unsafePayload("Initial tag");
  input.value = initialTagValue;
  const insertedIcons = [];
  const selectors = {
    $: (selector, root = document.body) => findAll(root, selector)[0] ?? null,
    $$: (selector, root = document.body) => findAll(root, selector),
  };
  const customRequire = (specifier) => {
    if (specifier.endsWith("/selectors")) return selectors;
    if (specifier.endsWith("/validation")) {
      return { escapeRegExp: (value) => value, makeDiacriticsRegExp: (value) => value };
    }
    if (specifier.endsWith("/events")) return { debounce: (callback) => callback };
    if (specifier.endsWith("/icons")) {
      return {
        insertIcon: (name, target) => {
          const icon = document.createElement("i");
          icon.className = "icon";
          icon.dataset.name = name;
          target.appendChild(icon);
          insertedIcons.push(name);
        },
      };
    }
    if (specifier === "sortablejs") return { __esModule: true, default: { create() {} } };
    return universalStub();
  };
  const { exports } = loadModule(
    files["panel/src/ts/components/inputs/tags-input.ts"],
    "tags-input.ts",
    customRequire,
    { document, Event: EventFixture, getComputedStyle: (element) => element.style },
  );
  const instance = new exports.TagsInput(input, { accept: "any" });
  const dropdown = instance.dropdown.childNodes[0];
  const initialTag = instance.list.childNodes[0];
  const updatedTagValue = unsafePayload("Updated tag");
  instance.value = updatedTagValue;
  const updatedTag = instance.list.childNodes[0];
  const remove = updatedTag.childNodes.find((node) => node.classList?.contains("tag-remove"));
  const snapshot = {
    dropdownText: dropdown.textContent,
    dropdownValue: dropdown.dataset.value,
    dropdownHasIcon: dropdown.querySelector(".icon") !== null,
    initialText: initialTag.textContent,
    updatedText: updatedTag.textContent,
    serializedValue: input.value,
    wrapperStructure:
      instance.field.childNodes.includes(instance.list) &&
      instance.field.childNodes.includes(instance.innerInput) &&
      instance.field.childNodes.includes(input),
  };
  remove.dispatchEvent(new EventFixture("mousedown"));
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    dropdownLiteral: snapshot.dropdownText === dropdownLabel,
    initialTagLiteral: snapshot.initialText === initialTagValue,
    updatedTagLiteral: snapshot.updatedText === updatedTagValue,
    dropdownValuePreserved: snapshot.dropdownValue === "fixture",
    iconPreserved: snapshot.dropdownHasIcon && insertedIcons.includes("shield"),
    serializedValuePreserved: snapshot.serializedValue === updatedTagValue,
    removeBehaviorPreserved: input.value === "" && instance.list.childNodes.length === 0,
    fieldStructurePreserved:
      snapshot.wrapperStructure && input.hidden === true && input.readOnly === true,
  };
}

function observeFormworkUpdates(files) {
  const document = new DocumentFixture();
  document.register("updater-component");
  const elements = Object.fromEntries(
    [
      ".update-status",
      ".spinner",
      ".current-version",
      ".current-version-name",
      ".new-version",
      ".new-version-name",
      "[data-command=install-updates]",
    ].map((selector) => [selector, document.createElement("div")]),
  );
  elements[".update-status"].dataset.installingText = unsafePayload("Installing");
  const requests = [];
  class RequestFixture {
    constructor(options, callback) {
      this.options = options;
      this.callback = callback;
      requests.push(this);
      if (options.url.endsWith("updates/check/")) {
        callback({
          status: "success",
          message: unsafePayload("Check response"),
          data: { uptodate: false, release: { name: unsafePayload("Version 2") } },
        });
      }
    }
  }
  const notifications = [];
  class NotificationFixture {
    constructor(...args) {
      this.args = args;
      notifications.push(this);
    }
    show() {
      this.shown = true;
    }
  }
  const insertedIcons = [];
  const customRequire = (specifier) => {
    if (specifier.endsWith("/selectors")) {
      return {
        $: (selector, root) => (root ? root.querySelector(selector) : (elements[selector] ?? null)),
      };
    }
    if (specifier.endsWith("/app")) {
      return { app: { config: { csrfToken: "fixture-token", baseUri: "/panel/" } } };
    }
    if (specifier.endsWith("/icons")) {
      return {
        insertIcon: (name, target) => {
          const icon = document.createElement("i");
          icon.className = "icon";
          target.appendChild(icon);
          insertedIcons.push(name);
        },
      };
    }
    if (specifier.endsWith("/notification")) return { Notification: NotificationFixture };
    if (specifier.endsWith("/request")) return { Request: RequestFixture };
    return universalStub();
  };
  const immediateWindow = {
    setTimeout: (callback) => {
      callback();
      return 1;
    },
  };
  const { exports } = loadModule(
    files["panel/src/ts/components/views/updates.ts"],
    "updates.ts",
    customRequire,
    { document, window: immediateWindow },
  );
  new exports.Updates();
  const checkSnapshot = {
    status: elements[".update-status"].textContent,
    version: elements[".new-version-name"].textContent,
    newVisible: elements[".new-version"].style.display,
  };
  elements["[data-command=install-updates]"].click();
  const installingText = elements[".update-status"].textContent;
  const updateRequest = requests.find((request) => request.options.url.endsWith("updates/update/"));
  updateRequest?.callback({
    status: "success",
    message: unsafePayload("Notification"),
    data: { status: unsafePayload("Installed status") },
  });
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    checkStatusLiteral: checkSnapshot.status === unsafePayload("Check response"),
    newVersionLiteral: checkSnapshot.version === unsafePayload("Version 2"),
    installingStatusLiteral: installingText === unsafePayload("Installing"),
    installedStatusLiteral:
      elements[".update-status"].textContent === unsafePayload("Installed status"),
    installedVersionLiteral:
      elements[".current-version-name"].textContent === unsafePayload("Version 2"),
    requestsPreserved:
      requests.length === 2 &&
      requests.every((request) => request.options.method === "POST") &&
      requests[0].options.url === "/panel/updates/check/" &&
      requests[1].options.url === "/panel/updates/update/" &&
      requests.every((request) => request.options.data["csrf-token"] === "fixture-token"),
    stateTransitionsPreserved:
      checkSnapshot.newVisible === "block" &&
      elements[".new-version"].style.display === "none" &&
      elements[".current-version"].style.display === "block",
    iconsPreserved: insertedIcons.includes("info") && insertedIcons.includes("check"),
    notificationPreserved:
      notifications.length === 1 &&
      notifications[0].shown === true &&
      notifications[0].args[0] === unsafePayload("Notification"),
  };
}

function observeLiljs(files) {
  const document = new DocumentFixture();
  const root = document.createElement("main");
  const text = document.createElement("span");
  text.setAttribute("lil-text", "name");
  const list = document.createElement("section");
  list.setAttribute("lil-list", "items");
  const stale = document.createElement("i");
  stale.textContent = "stale";
  list.appendChild(stale);
  root.append(text, list);
  const template = document.register("items", document.createElement("template"));
  template.content = document.createDocumentFragment();
  const row = document.createElement("span");
  row.setAttribute("lil-list-text", "title");
  template.content.appendChild(row);
  const initialName = unsafePayload("Initial name");
  const initialItem = unsafePayload("Initial item");
  const context = runScript(`${files["src/liljs.js"]}\nglobalThis.__liljs = liljs;`, "liljs.js", {
    document,
  });
  const app = context.__liljs(root, { name: initialName, items: [{ title: initialItem }] });
  const initialSnapshot = {
    name: text.textContent,
    items: list.childNodes.map((node) => node.textContent),
    listLength: list.childNodes.length,
  };
  const updatedName = unsafePayload("Updated name");
  const updatedItem = unsafePayload("Updated item");
  app.name = updatedName;
  app.items = [{ title: updatedItem }];
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    initialTextLiteral:
      initialSnapshot.name === initialName && initialSnapshot.items.includes(initialItem),
    updatedTextLiteral:
      text.textContent === updatedName &&
      list.childNodes.some((node) => node.textContent === updatedItem),
    initialListReplacementPreserved: initialSnapshot.listLength === 1,
    proxyUpdatePreserved:
      text.textContent.includes("Updated name") && !text.textContent.includes("Initial name"),
    listUpdatePreserved:
      list.childNodes.length === 1 &&
      list.childNodes[0]?.textContent.includes("Updated item") &&
      !list.textContent.includes("stale") &&
      !list.textContent.includes("Initial item"),
  };
}

function observeMnml(files) {
  const document = new DocumentFixture();
  const results = document.register("list_results");
  results.dataset.maxResults = "2";
  const context = runScript(
    `${files["static/js/search.js"]}\nglobalThis.__runSearch = runSearch;\nglobalThis.__setArchive = value => { archive_results = value; };`,
    "search.js",
    {
      document,
      fetch: () => Promise.resolve({ json: async () => ({ items: [] }) }),
      history: { pushState() {} },
      window: { location: { href: "https://fixture.example/search" } },
    },
  );
  const title = unsafePayload("Needle title");
  const content = unsafePayload("Needle content");
  const longContent = `needle-${"x".repeat(210)}`;
  context.__setArchive({
    items: [
      {
        title,
        content_text: content,
        date_published: "2024-01-02T00:00:00Z",
        url: "https://fixture.example/one",
      },
      {
        title: "Needle second",
        content_text: longContent,
        date_published: "2024-01-03T00:00:00Z",
        url: "https://fixture.example/two",
      },
      {
        title: "Needle third",
        content_text: "needle third",
        date_published: "2024-01-04T00:00:00Z",
        url: "https://fixture.example/three",
      },
    ],
  });
  context.__runSearch("needle");
  const paragraphs = [...results.childNodes];
  const first = paragraphs[0];
  const second = paragraphs[1];
  const firstBold = first?.querySelector("b");
  const firstSpans = first?.querySelectorAll("span") ?? [];
  const firstContent = firstSpans.at(-1);
  const secondSpans = second?.querySelectorAll("span") ?? [];
  const secondContent = secondSpans.at(-1);
  const snapshot = {
    count: paragraphs.length,
    display: results.style.display,
    boldText: firstBold?.textContent,
    contentText: firstContent?.textContent,
    href: first?.querySelector("a")?.href,
    truncated: secondContent?.textContent,
  };
  context.__runSearch("");
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    titleLiteral: snapshot.boldText === title,
    contentLiteral: snapshot.contentText === `: ${content}`,
    structuredTitlePreserved:
      firstBold?.tagName === "B" ||
      /title_node\.innerHTML\s*=\s*["'][^"']*<b>/.test(files["static/js/search.js"]),
    linkPreserved: snapshot.href === "https://fixture.example/one",
    truncationPreserved: snapshot.truncated === `: ${longContent.slice(0, 200)}...`,
    resultLimitPreserved: snapshot.count === 2,
    visibilityPreserved: snapshot.display === "block" && results.style.display === "none",
    clearingPreserved: results.childNodes.length === 0,
  };
}

function observeNbdime(files, kind) {
  const isDiff = kind === "diff";
  const filename = isDiff ? "packages/webapp/src/app/diff.ts" : "packages/webapp/src/app/merge.ts";
  const functionName = isDiff ? "onDiffRequestFailed" : "onMergeRequestFailed";
  const widgetName = isDiff ? "diffWidget" : "mergeWidget";
  const declaration = extractFunction(files[filename], functionName, filename);
  const document = new DocumentFixture();
  const root = document.register("nbdime-root");
  const stale = document.createElement("div");
  stale.textContent = "stale";
  root.appendChild(stale);
  const spinnerCalls = [];
  const context = runScript(
    `let ${widgetName} = { fixture: true };\n${declaration}\nglobalThis.__run = ${functionName};\nglobalThis.__widget = () => ${widgetName};`,
    `${kind}-failure.ts`,
    { document, toggleSpinner: (value) => spinnerCalls.push(value) },
  );
  const payload = unsafePayload(`${kind} response`);
  context.__run(payload);
  const pre = root.childNodes[0];
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    responseLiteral:
      root.childNodes.length === 1 && pre?.tagName === "PRE" && pre.textContent === payload,
    staleContentReplaced: !root.textContent.includes("stale"),
    widgetCleared: context.__widget() === null,
    spinnerStopped: spinnerCalls.length === 1 && spinnerCalls[0] === false,
  };
}

function observeWarewoolf(files) {
  const filename = "src/render.js";
  const declaration = extractFunction(files[filename], "updateFileList", filename);
  const document = new DocumentFixture();
  const chapterList = document.register("chapter-list");
  const referenceList = document.register("reference-list");
  const trashList = document.register("trash-list");
  const referenceHeader = document.register("reference-header");
  const trashHeader = document.register("trash-header");
  const sidebar = document.register("chapter-list-sidebar");
  referenceHeader.classList.add("trash-header-empty");
  trashHeader.classList.add("trash-header-empty");
  for (const list of [chapterList, referenceList, trashList]) {
    const stale = document.createElement("li");
    stale.textContent = "stale";
    list.appendChild(stale);
  }
  const titles = {
    chapter: unsafePayload("Chapter"),
    reference: unsafePayload("Reference"),
    trash: unsafePayload("Trash"),
  };
  const project = {
    chapters: [{ title: titles.chapter, hasUnsavedChanges: true }],
    reference: [{ title: titles.reference, hasUnsavedChanges: true }],
    trash: [{ title: titles.trash, hasUnsavedChanges: true }],
    activeChapterIndex: 0,
  };
  const opened = [];
  const renamed = [];
  const context = runScript(
    `${declaration}\nglobalThis.__run = updateFileList;`,
    "render-update-file-list.js",
    {
      document,
      project,
      displayChapterByIndex: (index) => opened.push(String(index)),
      changeChapterTitle: (index) => renamed.push(String(index)),
    },
  );
  context.__run();
  const items = [chapterList.childNodes[0], referenceList.childNodes[0], trashList.childNodes[0]];
  items[1].onclick.call(items[1]);
  items[1].ondblclick.call(items[1]);
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    chapterLiteral:
      items[0]?.textContent === titles.chapter || items[0]?.textContent === `${titles.chapter}*`,
    referenceLiteral:
      items[1]?.textContent === titles.reference ||
      items[1]?.textContent === `${titles.reference}*`,
    trashLiteral:
      items[2]?.textContent === titles.trash || items[2]?.textContent === `${titles.trash}*`,
    listsReplaced:
      [chapterList, referenceList, trashList].every((list) => list.childNodes.length === 1) &&
      items.every((item) => !item.textContent.includes("stale")),
    indexesPreserved: items.map((item) => String(item.dataset.chapIndex)).join(",") === "0,1,2",
    callbacksPreserved: opened.join(",") === "1" && renamed.join(",") === "1",
    unsavedMarkersPreserved: items.every((item) => item?.textContent.endsWith("*")),
    activeStatePreserved:
      items[0].classList.contains("activeChapter") && sidebar.scrollTop === items[0].offsetTop,
    headersPreserved:
      !referenceHeader.classList.contains("trash-header-empty") &&
      !trashHeader.classList.contains("trash-header-empty"),
  };
}

function observeXteve(files) {
  const document = new DocumentFixture();
  const log = document.register("content_log");
  const wrapper = document.register("box-wrapper");
  wrapper.scrollHeight = 440;
  const server = {
    log: {
      log: {
        first: unsafePayload("WARNING first"),
        second: unsafePayload("ERROR second"),
        third: unsafePayload("DEBUG third"),
      },
    },
  };
  const context = runScript(
    `${files["ts/logs_ts.ts"]}\nglobalThis.__showLogs = showLogs;`,
    "logs.ts",
    {
      document,
      SERVER: server,
      getObjKeys: (value) => Object.keys(value),
      Server: class {
        request() {}
      },
      setTimeout: (callback) => {
        callback();
        return 1;
      },
    },
  );
  context.__showLogs(true);
  const entries = [...log.childNodes];
  const snapshot = {
    text: entries.map((entry) => entry.textContent),
    classes: entries.map((entry) => entry.className),
    tags: entries.map((entry) => entry.tagName),
    scrollTop: wrapper.scrollTop,
  };
  server.log.log = { replacement: "replacement entry" };
  context.__showLogs(false);
  return {
    candidateExecuted: true,
    noActiveMarkup: document.active === false,
    entriesLiteral:
      snapshot.text.length === 3 &&
      [
        unsafePayload("WARNING first"),
        unsafePayload("ERROR second"),
        unsafePayload("DEBUG third"),
      ].every((value) => snapshot.text.includes(value)),
    preElementsPreserved: snapshot.tags.every((tag) => tag === "PRE"),
    severityClassesPreserved: snapshot.classes.join(",") === "warningMsg,errorMsg,debugMsg",
    orderPreserved:
      snapshot.text[0]?.includes("WARNING first") && snapshot.text[2]?.includes("DEBUG third"),
    bottomScrollPreserved: snapshot.scrollTop === 440,
    replacementPreserved: log.childNodes.length === 1 && log.textContent === "replacement entry",
  };
}

const contracts = {
  "alps-message-reader-inert-parsing": {
    observe: observeAlps,
    acceptance: [
      ["All three message paths use the inert helper", "allContextsUseHelper"],
      ["Untrusted HTML never enters a live DOM sink", "noLiveMarkupActivation"],
      ["Returned text contains no markup", "markupRemoved"],
    ],
    regressions: [
      ["Readable text is preserved", "readableTextPreserved"],
      ["Block and line breaks are preserved", "blockBreaksPreserved"],
      ["Excluded element content is removed", "excludedContentRemoved"],
      ["Empty input remains empty", "emptyInputPreserved"],
    ],
  },
  "formwork-tag-label-text": {
    observe: observeFormworkTags,
    acceptance: [
      ["Tag and option values cannot activate markup", "noActiveMarkup"],
      ["Dropdown labels render literally", "dropdownLiteral"],
      ["Initial tags render literally", "initialTagLiteral"],
      ["Updated tags render literally", "updatedTagLiteral"],
    ],
    regressions: [
      ["Dropdown values are preserved", "dropdownValuePreserved"],
      ["Option icons are preserved", "iconPreserved"],
      ["Serialized tag values are preserved", "serializedValuePreserved"],
      ["Tag removal remains functional", "removeBehaviorPreserved"],
      ["Field structure remains functional", "fieldStructurePreserved"],
    ],
  },
  "formwork-update-status-text": {
    observe: observeFormworkUpdates,
    acceptance: [
      ["Update responses cannot activate markup", "noActiveMarkup"],
      ["Check status renders literally", "checkStatusLiteral"],
      ["Release name renders literally", "newVersionLiteral"],
      ["Installing status renders literally", "installingStatusLiteral"],
      ["Installed status renders literally", "installedStatusLiteral"],
      ["Installed version renders literally", "installedVersionLiteral"],
    ],
    regressions: [
      ["Update requests retain their contract", "requestsPreserved"],
      ["Update state transitions remain functional", "stateTransitionsPreserved"],
      ["Status icons remain functional", "iconsPreserved"],
      ["Completion notifications remain functional", "notificationPreserved"],
    ],
  },
  "liljs-element-text-rendering": {
    observe: observeLiljs,
    acceptance: [
      ["Bound values cannot activate markup", "noActiveMarkup"],
      ["Initial values render literally", "initialTextLiteral"],
      ["Updated values render literally", "updatedTextLiteral"],
    ],
    regressions: [
      ["Initial list content replaces stale content", "initialListReplacementPreserved"],
      ["Proxy text updates remain functional", "proxyUpdatePreserved"],
      ["Proxy list updates remain functional", "listUpdatePreserved"],
    ],
  },
  "mnml-search-result-text-rendering": {
    observe: observeMnml,
    acceptance: [
      ["Search data cannot activate markup", "noActiveMarkup"],
      ["Search titles render literally", "titleLiteral"],
      ["Search excerpts render literally", "contentLiteral"],
    ],
    regressions: [
      ["Bold title structure is preserved", "structuredTitlePreserved"],
      ["Result links are preserved", "linkPreserved"],
      ["Excerpt truncation is preserved", "truncationPreserved"],
      ["Result limits are preserved", "resultLimitPreserved"],
      ["Visibility behavior is preserved", "visibilityPreserved"],
      ["Empty searches clear results", "clearingPreserved"],
    ],
  },
  "nbdime-diff-response-text": {
    observe: (files) => observeNbdime(files, "diff"),
    acceptance: [
      ["Diff errors cannot activate markup", "noActiveMarkup"],
      ["Diff errors render literally", "responseLiteral"],
    ],
    regressions: [
      ["Previous diff output is replaced", "staleContentReplaced"],
      ["Diff widget state is cleared", "widgetCleared"],
      ["Diff spinner stops", "spinnerStopped"],
    ],
  },
  "nbdime-merge-response-text": {
    observe: (files) => observeNbdime(files, "merge"),
    acceptance: [
      ["Merge errors cannot activate markup", "noActiveMarkup"],
      ["Merge errors render literally", "responseLiteral"],
    ],
    regressions: [
      ["Previous merge output is replaced", "staleContentReplaced"],
      ["Merge widget state is cleared", "widgetCleared"],
      ["Merge spinner stops", "spinnerStopped"],
    ],
  },
  "warewoolf-chapter-title-rendering": {
    observe: observeWarewoolf,
    acceptance: [
      ["Chapter titles cannot activate markup", "noActiveMarkup"],
      ["Chapter titles render literally", "chapterLiteral"],
      ["Reference titles render literally", "referenceLiteral"],
      ["Trash titles render literally", "trashLiteral"],
    ],
    regressions: [
      ["All lists replace stale content", "listsReplaced"],
      ["Chapter indexes are preserved", "indexesPreserved"],
      ["Open and rename callbacks are preserved", "callbacksPreserved"],
      ["Unsaved chapter markers are preserved", "unsavedMarkersPreserved"],
      ["Active chapter state is preserved", "activeStatePreserved"],
      ["Reference and trash headers are preserved", "headersPreserved"],
    ],
  },
  "xteve-log-entry-rendering": {
    observe: observeXteve,
    acceptance: [
      ["Log entries cannot activate markup", "noActiveMarkup"],
      ["Log entries render literally", "entriesLiteral"],
    ],
    regressions: [
      ["Logs remain preformatted", "preElementsPreserved"],
      ["Severity classes are preserved", "severityClassesPreserved"],
      ["Log order is preserved", "orderPreserved"],
      ["Bottom scrolling is preserved", "bottomScrollPreserved"],
      ["Refreshes replace old entries", "replacementPreserved"],
    ],
  },
};

export const unsafeHtmlCaseIds = Object.freeze(Object.keys(contracts));

export async function gradeUnsafeHtmlCandidate(id, files) {
  const contract = contracts[id];
  if (!contract) throw new Error(`Unknown unsafe HTML case: ${id}`);
  try {
    const observed = await contract.observe(files);
    return result(observed, contract.acceptance, contract.regressions);
  } catch (error) {
    return failedResult(error);
  }
}
