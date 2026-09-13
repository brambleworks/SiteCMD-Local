import { createHash } from "node:crypto";
import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { extensionHolder } from "./confirmatory-dom.mjs";

const input = JSON.parse(readFileSync(0, "utf8"));
const workRoot = process.env.SITECMD_BENCHMARK_WORK_ROOT ?? "/work";
const entry = path.join(workRoot, input.entry);
const source = readFileSync(entry, "utf8");
const sourceSha256 = createHash("sha256").update(source).digest("hex");
const hostRequire = createRequire(import.meta.url);
const compiler = process.env.SITECMD_BENCHMARK_TYPESCRIPT ?? "/compiler/typescript.cjs";
const ts = hostRequire(compiler);

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

function transpile(customRequire, globals = {}, compilerOptions = {}) {
  const output = ts.transpileModule(source, {
    fileName: entry,
    compilerOptions: {
      allowJs: true,
      esModuleInterop: true,
      experimentalDecorators: true,
      jsx: ts.JsxEmit.React,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      ...compilerOptions,
    },
  });
  const module = { exports: {} };
  const context = vm.createContext({
    Buffer,
    console: { log() {}, warn() {}, error() {} },
    exports: module.exports,
    module,
    process: { env: {} },
    require: customRequire,
    setTimeout,
    clearTimeout,
    URL,
    ...globals,
  });
  const wrapper = new vm.Script(
    `(function (exports, require, module, __filename, __dirname) {${output.outputText}\n})`,
    { filename: entry },
  ).runInContext(context, { timeout: 3000 });
  wrapper(module.exports, customRequire, module, entry, path.dirname(entry));
  return module.exports;
}

function response() {
  return {
    statusCode: 200,
    body: null,
    headers: {},
    status(value) {
      this.statusCode = value;
      return this;
    },
    json(value) {
      this.body = value;
      return this;
    },
    send(value) {
      this.body = value;
      return this;
    },
    sendFile() {
      return this;
    },
    sendStatus(value) {
      this.statusCode = value;
      return this;
    },
    header(name, value) {
      this.headers[name.toLowerCase()] = String(value);
      return this;
    },
  };
}

function childProcess() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => {};
  queueMicrotask(() => {
    child.stdout.emit("data", Buffer.from("Done\n"));
    child.emit("close", 0);
  });
  return child;
}

function loadClaudeServer(platform = "linux") {
  const routes = new Map();
  const middlewares = [];
  const spawnCalls = [];
  const listenCalls = [];
  const app = {
    get(route, handler) {
      routes.set(`GET ${route}`, handler);
    },
    post(route, handler) {
      routes.set(`POST ${route}`, handler);
    },
    use(...args) {
      const handler = args.find((value) => typeof value === "function");
      if (handler) middlewares.push(handler);
    },
    listen(port, host, callback) {
      if (typeof host === "function") {
        callback = host;
        host = undefined;
      }
      listenCalls.push({ port, host });
      callback?.();
      return { close() {} };
    },
  };
  const express = () => app;
  express.json = () => (_req, _res, next) => next();
  express.static = () => (_req, _res, next) => next();
  const chalk = new Proxy(
    {},
    {
      get() {
        return (...values) => values.join(" ");
      },
    },
  );
  const customRequire = (specifier) => {
    if (specifier === "express") return express;
    if (specifier === "chalk") return chalk;
    if (specifier === "path") return path;
    if (specifier === "fs")
      return {
        existsSync: (value) => String(value).includes("/.claude/agents/"),
        readFileSync: () => "",
        writeFileSync() {},
      };
    if (specifier === "child_process")
      return {
        spawn(command, args, options = {}) {
          spawnCalls.push({ command, args, options });
          return childProcess();
        },
      };
    return universalStub();
  };
  const module = { exports: {} };
  const processValue = {
    cwd: () => "/work",
    env: {},
    platform,
  };
  const context = vm.createContext({
    Buffer,
    console: { log() {}, warn() {}, error() {} },
    Date,
    Math,
    module,
    exports: module.exports,
    process: processValue,
    require: customRequire,
    setTimeout() {
      return 1;
    },
    clearTimeout() {},
    __dirname: path.dirname(entry),
    __filename: entry,
  });
  const executableSource = source.replace(/^#![^\n]*\n/, "");
  const wrapper = new vm.Script(
    `(function (exports, require, module, __filename, __dirname) {${executableSource}\n})`,
    { filename: entry },
  ).runInContext(context, { timeout: 3000 });
  wrapper(module.exports, customRequire, module, entry, path.dirname(entry));
  return { app, routes, middlewares, spawnCalls, listenCalls };
}

async function settle() {
  for (let index = 0; index < 6; index++) await new Promise((resolve) => setImmediate(resolve));
}

async function callRoute(server, method, route, body, params = {}) {
  const handler = server.routes.get(`${method} ${route}`);
  if (!handler) throw new Error(`Missing route ${method} ${route}`);
  const result = response();
  await handler({ body, params, headers: {}, method }, result);
  await settle();
  return result;
}

async function probeClaudeShell() {
  const maliciousServer = loadClaudeServer();
  const malicious = await callRoute(maliciousServer, "POST", "/api/install-agent", {
    agentName: "tools/reviewer;touch /tmp/sitecmd-probe",
  });
  const maliciousAgentRejected =
    malicious.statusCode === 400 && maliciousServer.spawnCalls.length === 0;

  const agentServer = loadClaudeServer();
  const agentName = "development-team/frontend-developer";
  const validAgent = await callRoute(agentServer, "POST", "/api/install-agent", { agentName });
  const agentCall = agentServer.spawnCalls[0];
  const agentArgumentsLiteral =
    agentCall?.options?.shell !== true &&
    agentCall?.args?.filter((value) => value === agentName).length === 1;

  const promptServer = loadClaudeServer();
  const prompt = "Review this safely; touch /tmp/sitecmd-probe";
  const started = await callRoute(promptServer, "POST", "/api/execute", {
    prompt,
    mode: "local",
    agent: "development-team/frontend-developer",
  });
  const promptCall = promptServer.spawnCalls[0];
  const promptArgumentsLiteral =
    promptCall?.options?.shell !== true &&
    promptCall?.args?.length === 1 &&
    promptCall.args[0] === prompt;
  const windowsAgentServer = loadClaudeServer("win32");
  await callRoute(windowsAgentServer, "POST", "/api/install-agent", { agentName });
  const windowsPromptServer = loadClaudeServer("win32");
  await callRoute(windowsPromptServer, "POST", "/api/execute", {
    prompt,
    mode: "local",
    agent: "development-team/frontend-developer",
  });
  const windowsAgentCall = windowsAgentServer.spawnCalls[0];
  const windowsPromptCall = windowsPromptServer.spawnCalls[0];
  const task = started.body?.taskId
    ? await callRoute(promptServer, "GET", "/api/task/:taskId", undefined, {
        taskId: started.body.taskId,
      })
    : null;
  return {
    maliciousAgentRejected,
    agentArgumentsLiteral,
    promptArgumentsLiteral,
    windowsCommandResolutionSafe:
      windowsAgentCall?.command === "npx.cmd" &&
      windowsAgentCall?.options?.shell !== true &&
      windowsPromptCall?.command === "claude.cmd" &&
      windowsPromptCall?.options?.shell !== true,
    validAgentPreserved: validAgent.statusCode === 200 && validAgent.body?.success === true,
    validPromptPreserved: started.statusCode === 200 && started.body?.success === true,
    taskLifecyclePreserved:
      task?.body?.task?.status === "completed" &&
      task.body.task.progress === 100 &&
      task.body.task.output.includes("completed"),
  };
}

function runMiddleware(middleware, origin) {
  const result = response();
  let completed = false;
  middleware({ method: "GET", headers: origin ? { origin } : {} }, result, () => {
    completed = true;
  });
  return { ...result, completed };
}

function probeClaudeLoopback() {
  const server = loadClaudeServer();
  const cors = server.middlewares.find((middleware) => {
    const result = runMiddleware(middleware, "https://outside.example");
    return result.statusCode === 403 || "access-control-allow-origin" in result.headers;
  });
  if (!cors) throw new Error("Local origin middleware was not found");
  const outside = runMiddleware(cors, "https://outside.example");
  const localhost = runMiddleware(cors, "http://localhost:3444");
  const loopback = runMiddleware(cors, "http://127.0.0.1:3444");
  const listen = server.listenCalls[0];
  return {
    sourceSha256,
    loopbackBound: listen?.host === "127.0.0.1",
    onlyLocalOriginsAllowed:
      outside.statusCode === 403 && !outside.headers["access-control-allow-origin"],
    localhostOriginPreserved:
      localhost.completed &&
      localhost.headers["access-control-allow-origin"] === "http://localhost:3444",
    loopbackOriginPreserved:
      loopback.completed &&
      loopback.headers["access-control-allow-origin"] === "http://127.0.0.1:3444",
    serverStarts: Number(listen?.port) === 3444,
  };
}

class Stream {
  constructor() {
    this.observers = [];
  }

  pipe(...operators) {
    return operators.reduce((value, operator) => operator(value), this);
  }

  subscribe(observer) {
    const next = typeof observer === "function" ? observer : observer?.next?.bind(observer);
    if (next) this.observers.push(next);
    return { unsubscribe: () => (this.observers = this.observers.filter((item) => item !== next)) };
  }

  next(value) {
    for (const observer of [...this.observers]) observer(value);
  }

  complete() {}
}

class Subject extends Stream {}

function mapStream(project) {
  return (sourceStream) => {
    const output = new Stream();
    sourceStream.subscribe((value) => output.next(project(value)));
    return output;
  };
}

function filterStream(predicate) {
  return (sourceStream) => {
    const output = new Stream();
    sourceStream.subscribe((value) => {
      if (predicate(value)) output.next(value);
    });
    return output;
  };
}

function tapStream(callback) {
  return (sourceStream) => {
    const output = new Stream();
    sourceStream.subscribe((value) => {
      callback(value);
      output.next(value);
    });
    return output;
  };
}

function combineLatestWith(other) {
  return (sourceStream) => {
    const output = new Stream();
    let left;
    let right;
    let hasLeft = false;
    let hasRight = false;
    sourceStream.subscribe((value) => {
      left = value;
      hasLeft = true;
      if (hasRight) output.next([left, right]);
    });
    other.subscribe((value) => {
      right = value;
      hasRight = true;
      if (hasLeft) output.next([left, right]);
    });
    return output;
  };
}

function mergeStreams(...streams) {
  const output = new Stream();
  for (const stream of streams) stream.subscribe((value) => output.next(value));
  return output;
}

function distinctUntilChanged() {
  return (sourceStream) => {
    const output = new Stream();
    let previous = Symbol("unset");
    sourceStream.subscribe((value) => {
      if (!Object.is(value, previous)) {
        previous = value;
        output.next(value);
      }
    });
    return output;
  };
}

function fromEvent(target, name) {
  const output = new Stream();
  target.addEventListener(name, (event) => output.next(event));
  return output;
}

function decodeSpaces(value) {
  return String(value).replaceAll("&nbsp;", "\u00a0");
}

function suggestionElement() {
  const state = { active: false, value: "", mode: null };
  return {
    state,
    get innerText() {
      return state.value;
    },
    set innerHTML(value) {
      state.mode = "html";
      state.value = decodeSpaces(value);
      state.active = /<script\b|\son[a-z]+\s*=/i.test(value);
    },
    set textContent(value) {
      state.mode = "text";
      state.value = String(value);
      state.active = false;
    },
  };
}

function queryElement(value) {
  const listeners = new Map();
  return {
    value,
    selectionStart: value.length,
    addEventListener(name, callback) {
      const entries = listeners.get(name) ?? [];
      entries.push(callback);
      listeners.set(name, entries);
    },
    emit(name) {
      for (const callback of listeners.get(name) ?? []) callback({ type: name });
    },
  };
}

function loadMaterial(query) {
  const operators = {
    Observable: Stream,
    Subject,
    asyncScheduler: {},
    combineLatestWith,
    distinctUntilChanged,
    filter: filterStream,
    finalize: () => (stream) => stream,
    fromEvent,
    map: mapStream,
    merge: mergeStreams,
    observeOn: () => (stream) => stream,
    tap: tapStream,
  };
  return transpile((specifier) => {
    if (specifier === "rxjs") return operators;
    if (specifier === "../../_") return { getComponentElement: () => query };
    if (specifier === "~/integrations") return { isSearchResultMessage: () => true };
    return universalStub();
  });
}

function renderSuggestion(queryValue, suggestion) {
  const query = queryElement(queryValue);
  const element = suggestionElement();
  const worker = new Subject();
  const keyboard = new Subject();
  const module = loadMaterial(query);
  module.mountSearchSuggest(element, { worker$: worker, keyboard$: keyboard }).subscribe(() => {});
  query.emit("focus");
  worker.next({ data: { suggest: [suggestion] } });
  return { query, element, keyboard };
}

function probeMaterial() {
  const active = renderSuggestion("hello <scr", "<script>sitecmdProbe()</script>");
  const ordinary = renderSuggestion("hello wo", "world");
  ordinary.keyboard.next({ mode: "search", type: "ArrowRight" });
  return {
    activeMarkupPrevented: !active.element.state.active,
    ordinarySuggestionPreserved:
      ordinary.element.state.value.includes("hello") &&
      ordinary.element.state.value.includes("world"),
    whitespacePreserved: /^hello[\s\u00a0]world$/u.test(ordinary.element.state.value),
    rightArrowPreserved: ordinary.query.value === ordinary.element.innerText,
  };
}

function loadYamcs(state) {
  const extensionService = {
    isDisablingReloadOnNavigation() {
      return false;
    },
  };
  const angular = {
    Component: () => (target) => target,
    Input: () => () => {},
    ViewChild: () => () => {},
    inject(token) {
      return token?.name === "ExtensionService" ? extensionService : {};
    },
  };
  class ConfigService {}
  class ExtensionService {}
  class WebappSdkModule {}
  const document = {
    createElement(name) {
      state.created.push(name);
      return { tagName: name };
    },
  };
  const exports = transpile(
    (specifier) => {
      if (specifier === "@angular/core") return angular;
      if (specifier === "@yamcs/webapp-sdk")
        return { ConfigService, ExtensionService, WebappSdkModule };
      return universalStub();
    },
    { document },
  );
  return { ExtensionComponent: exports.ExtensionComponent, extensionService, document };
}

function yamcsInstance() {
  const state = { active: false, created: [], innerHtmlWrites: [] };
  const loaded = loadYamcs(state);
  const holder = extensionHolder(state, loaded.document);
  const component = new loaded.ExtensionComponent();
  component.customElementHolder = { nativeElement: holder };
  component.subroute = "details";
  return { state, holder, component };
}

function probeYamcs() {
  const malicious = yamcsInstance();
  malicious.component.loadExtension("safe-widget></safe-widget><img onerror=sitecmdProbe>");
  const valid = yamcsInstance();
  valid.component.loadExtension("sample-widget");
  const element = valid.holder.firstChild;
  const reloaded = yamcsInstance();
  reloaded.component.extension = "sample-widget";
  reloaded.component.ngOnChanges({ extension: { currentValue: "sample-widget" } });
  return {
    malformedNameRejected:
      malicious.holder.children.length === 0 && malicious.state.created.length === 0,
    markupInjectionPrevented: !malicious.state.active,
    validElementCreated:
      valid.holder.children.length === 1 &&
      String(element?.tagName).toLowerCase() === "sample-widget",
    extensionPropertiesPreserved:
      element?.subroute === "details" &&
      element?.extensionService === valid.component.extensionService,
    reloadBehaviorPreserved: reloaded.holder.children.length === 1,
  };
}

function decodeHtmlEntities(value) {
  return String(value)
    .replace(/&#(\d+);/g, (_match, number) => String.fromCodePoint(Number(number)))
    .replace(/&#x([a-f0-9]+);/gi, (_match, number) => String.fromCodePoint(parseInt(number, 16)))
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&#39;", "'")
    .replaceAll("&amp;", "&");
}

function probeLiveAtlas() {
  const state = { appended: 0, textareaCreated: 0 };
  const textarea = {
    value: "",
    textContent: "",
    set innerHTML(value) {
      const decoded = decodeHtmlEntities(value);
      this.value = decoded;
      this.textContent = decoded;
    },
  };
  const document = {
    createRange() {
      return universalStub();
    },
    createElement(name) {
      if (name === "textarea") {
        state.textareaCreated++;
        return textarea;
      }
      return {};
    },
    appendChild() {
      state.appended++;
    },
  };
  const module = transpile(() => universalStub(), { document });
  const active = module.decodeHTMLEntities("&lt;img src=x onerror=&quot;sitecmdProbe()&quot;&gt;");
  return {
    sourceSha256,
    activeMarkupPrevented: typeof active === "string" && state.appended === 0,
    namedEntitiesDecoded: module.decodeHTMLEntities("Tom &amp; Jerry") === "Tom & Jerry",
    numericEntitiesDecoded: module.decodeHTMLEntities("&#65;&#x42;") === "AB",
    ordinaryTextPreserved: module.decodeHTMLEntities("ordinary text") === "ordinary text",
    detachedDecoderPreserved: state.textareaCreated === 1 && state.appended === 0,
  };
}

try {
  const output =
    input.operation === "claude-code-templates-shell-boundary"
      ? await probeClaudeShell()
      : input.operation === "material-search-suggestion-text"
        ? probeMaterial()
        : input.operation === "yamcs-extension-element-construction"
          ? probeYamcs()
          : input.operation === "claude-code-templates-loopback-control"
            ? probeClaudeLoopback()
            : input.operation === "liveatlas-entity-decoder-control"
              ? probeLiveAtlas()
              : (() => {
                  throw new Error("Unsupported Node confirmatory probe");
                })();
  process.stdout.write(JSON.stringify(output));
} catch (error) {
  process.stdout.write(JSON.stringify({ error: error.name, message: error.message }));
}
