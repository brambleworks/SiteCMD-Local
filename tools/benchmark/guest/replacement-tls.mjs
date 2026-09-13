import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

const directory = path.dirname(fileURLToPath(import.meta.url));
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

function loadModule(source, filename, customRequire, environment = {}) {
  const rewritten = source.replaceAll(
    "import.meta.url",
    JSON.stringify(`file:///work/${filename}`),
  );
  const output = ts.transpileModule(rewritten, {
    fileName: filename,
    reportDiagnostics: true,
    compilerOptions: {
      allowJs: true,
      esModuleInterop: true,
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  });
  if (
    output.diagnostics?.some((diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error)
  ) {
    throw new Error("Candidate does not parse");
  }
  const module = { exports: {} };
  const context = vm.createContext({
    Buffer,
    URL,
    console: { log() {}, warn() {}, error() {} },
    exports: module.exports,
    module,
    process: { env: { ...environment }, emitWarning() {} },
    require: customRequire,
    setTimeout,
    clearTimeout,
    queueMicrotask,
    __filename: `/work/${filename}`,
    __dirname: path.posix.dirname(`/work/${filename}`),
  });
  const wrapper = new vm.Script(`(function (exports, require, module) {${output.outputText}\n})`, {
    filename: `/work/${filename}`,
  }).runInContext(context, { timeout: 3000 });
  wrapper(module.exports, customRequire, module);
  return module.exports;
}

function secureTlsOptions(options) {
  return options && options.rejectUnauthorized !== false;
}

function pythonProbe(id, source) {
  const response = spawnSync(
    "/usr/bin/python3",
    [path.join(directory, "replacement-tls-python.py")],
    {
      input: JSON.stringify({ id, source }),
      encoding: "utf8",
      timeout: 10000,
      maxBuffer: 1024 * 1024,
    },
  );
  if (response.status !== 0)
    throw new Error(response.stderr || `Python probe exited ${response.status}`);
  const lines = response.stdout.trim().split("\n");
  const parsed = JSON.parse(lines.at(-1));
  if (parsed.error) throw new Error(parsed.error);
  return parsed.observed;
}

function stripCStyleComments(source) {
  let output = "";
  let quote = null;
  let lineComment = false;
  let blockComment = false;
  let escaped = false;
  for (let index = 0; index < source.length; index++) {
    const value = source[index];
    const next = source[index + 1];
    if (lineComment) {
      if (value === "\n") {
        lineComment = false;
        output += value;
      } else output += " ";
      continue;
    }
    if (blockComment) {
      if (value === "*" && next === "/") {
        output += "  ";
        index += 1;
        blockComment = false;
      } else output += value === "\n" ? "\n" : " ";
      continue;
    }
    if (quote) {
      output += value;
      if (escaped) escaped = false;
      else if (value === "\\" && quote !== "`") escaped = true;
      else if (value === quote) quote = null;
      continue;
    }
    if (value === "/" && next === "/") {
      output += "  ";
      index += 1;
      lineComment = true;
    } else if (value === "/" && next === "*") {
      output += "  ";
      index += 1;
      blockComment = true;
    } else {
      output += value;
      if (value === '"' || value === "'" || value === "`") quote = value;
    }
  }
  return output;
}

function stripRubyComments(source) {
  let output = "";
  let quote = null;
  let escaped = false;
  for (let index = 0; index < source.length; index++) {
    const value = source[index];
    if (quote) {
      output += value;
      if (escaped) escaped = false;
      else if (value === "\\") escaped = true;
      else if (value === quote) quote = null;
      continue;
    }
    if (value === '"' || value === "'") {
      quote = value;
      output += value;
      continue;
    }
    if (value === "#") {
      while (index < source.length && source[index] !== "\n") {
        output += " ";
        index += 1;
      }
      if (index < source.length) output += "\n";
      continue;
    }
    output += value;
  }
  return output;
}

function observeBigflow(files) {
  return pythonProbe("bigflow-deploy-tls-verification", files["bigflow/deploy.py"]);
}

function observeBlackduck(files) {
  return pythonProbe("blackduck-client-tls-verification", files["blackduck/HubRestApi.py"]);
}

function functionBlock(source, signature) {
  const start = source.indexOf(signature);
  if (start < 0) return "";
  const open = source.indexOf("{", start);
  if (open < 0) return "";
  let depth = 0;
  let quote = null;
  let escaped = false;
  for (let index = open; index < source.length; index++) {
    const value = source[index];
    if (quote) {
      if (escaped) escaped = false;
      else if (value === "\\") escaped = true;
      else if (value === quote) quote = null;
      continue;
    }
    if (value === '"' || value === "'" || value === "`") {
      quote = value;
      continue;
    }
    if (value === "{") depth += 1;
    if (value === "}") depth -= 1;
    if (depth === 0) return source.slice(start, index + 1);
  }
  return "";
}

function observeAlist(files) {
  const source = stripCStyleComments(files["server/handles/ldap_login.go"]);
  const config = stripCStyleComments(files["internal/conf/config.go"]);
  const dial = functionBlock(source, "func dial(");
  const defaultConfig = functionBlock(config, "func DefaultConfig(");
  const defaultSetting = /TlsInsecureSkipVerify\s*:\s*(true|false)/.exec(defaultConfig)?.[1];
  const skipValues = [...dial.matchAll(/InsecureSkipVerify\s*(?::|=)\s*([^,}\s]+)/g)].map(
    (match) => match[1],
  );
  const directBypass = skipValues.includes("true");
  const configured = /InsecureSkipVerify\s*:\s*conf\.Conf\.TlsInsecureSkipVerify/.test(dial);
  const omittedOrFalse = skipValues.length === 0 || skipValues.every((value) => value === "false");
  return {
    secureDefault: !directBypass && defaultSetting !== "true" && (configured || omittedOrFalse),
    ldapsPreserved:
      /HasPrefix\(ldapServer,\s*"ldaps:\/\/"\)/.test(dial) &&
      /ldap\.DialTLS\("tcp",\s*ldapServer/.test(dial),
    ldapPreserved:
      /HasPrefix\(ldapServer,\s*"ldap:\/\/"\)/.test(dial) &&
      /ldap\.Dial\("tcp",\s*ldapServer\)/.test(dial),
    configuredDefaultBound: !configured || defaultSetting === "false",
  };
}

function observeGobot(files) {
  const source = stripCStyleComments(files["platforms/mqtt/mqtt_adaptor.go"]);
  const create = functionBlock(source, "func (a *Adaptor) createClientOptions(");
  const tlsConfig = functionBlock(source, "func (a *Adaptor) newTLSConfig(");
  const skipValues = [...tlsConfig.matchAll(/InsecureSkipVerify\s*(?::|=)\s*([^,}\s]+)/g)].map(
    (match) => match[1],
  );
  return {
    verificationEnabled: skipValues.length === 0 || skipValues.every((value) => value === "false"),
    tlsPathPreserved:
      /if\s+a\.UseSSL\(\)/.test(create) && /SetTLSConfig\(a\.newTLSConfig\(\)\)/.test(create),
    serverTrustPreserved:
      /RootCAs\s*:\s*certpool/.test(tlsConfig) && /AppendCertsFromPEM/.test(tlsConfig),
    clientCertificatesPreserved:
      /tls\.LoadX509KeyPair/.test(tlsConfig) && /Certificates\s*:\s*certs/.test(tlsConfig),
  };
}

function observeCssParser(files) {
  const source = stripRubyComments(files["lib/css_parser/parser.rb"]);
  const remote = source.slice(
    source.indexOf("def read_remote_file"),
    source.indexOf("\n    end", source.indexOf("def read_remote_file")) + 8,
  );
  return {
    verificationEnabled:
      !/VERIFY_NONE/.test(remote) && !/verify_(?:mode|hostname)\s*=\s*(?:false|0|nil)/.test(remote),
    httpsPreserved:
      /uri\.scheme\s*==\s*['"]https['"]/.test(remote) && /http\.use_ssl\s*=\s*true/.test(remote),
    requestPreserved: /http\.get\(uri\.request_uri/.test(remote),
    redirectAndCompressionPreserved:
      /read_remote_file\s+Addressable::URI/.test(remote) &&
      /Zlib::GzipReader/.test(remote) &&
      /Zlib::Inflate/.test(remote),
  };
}

function websocketCapture(source, options) {
  const calls = [];
  class WebSocketFixture {
    static OPEN = 1;
    constructor(...args) {
      calls.push(args);
      this.readyState = 1;
    }
    send() {}
    terminate() {}
  }
  const customRequire = (specifier) => {
    if (specifier === "isomorphic-ws") return WebSocketFixture;
    if (specifier === "graphql") return { print: () => "query Fixture" };
    if (specifier === "@graphql-tools/utils") {
      return { observableToAsyncIterable: (observable) => observable };
    }
    return universalStub();
  };
  const exports = loadModule(source, "packages/executors/legacy-ws/src/index.ts", customRequire);
  const executor = exports.buildWSLegacyExecutor(
    "wss://graphql.example/socket",
    WebSocketFixture,
    options,
  );
  const subscription = executor({
    document: {},
    variables: { fixture: true },
    operationName: "Fixture",
  });
  subscription.subscribe({ error() {}, next() {}, complete() {} });
  return calls[0];
}

function observeGraphql(files) {
  const source = files["packages/executors/legacy-ws/src/index.ts"];
  const headers = { Authorization: "Bearer fixture" };
  const defaultCall = websocketCapture(source, undefined);
  const configuredCall = websocketCapture(source, { headers });
  const options = defaultCall?.[2];
  return {
    secureDefault: secureTlsOptions(options),
    endpointAndProtocolPreserved:
      defaultCall?.[0] === "wss://graphql.example/socket" && defaultCall?.[1] === "graphql-ws",
    websocketOptionsPreserved:
      options?.followRedirects === true && options?.skipUTF8Validation === true,
    headersPreserved: configuredCall?.[2]?.headers === headers,
  };
}

class PoolFixture {
  static instances = [];
  constructor(options) {
    this.options = options;
    this.events = [];
    this.queries = [];
    this.client = {
      released: false,
      query: async (text) => ({ rows: [{ text }] }),
      release() {
        this.released = true;
      },
    };
    PoolFixture.instances.push(this);
  }
  on(...args) {
    this.events.push(args);
  }
  async query(text, params) {
    this.queries.push({ text, params });
    return { rows: [{ id: 1 }], rowCount: 1 };
  }
  async connect() {
    return this.client;
  }
  async end() {
    this.ended = true;
  }
}

function loadKaarya(source, environment) {
  PoolFixture.instances = [];
  const exports = loadModule(
    source,
    "server/src/db-pg.js",
    (specifier) => {
      if (specifier === "pg") return { Pool: PoolFixture };
      if (specifier === "dotenv") return { config() {} };
      return universalStub();
    },
    environment,
  );
  const pool = exports.getPool();
  return { exports, pool };
}

async function observeKaarya(files) {
  const source = files["server/src/db-pg.js"];
  const production = loadKaarya(source, {
    DATABASE_URL: "postgres://fixture",
    NODE_ENV: "production",
  });
  const required = loadKaarya(source, { DATABASE_URL: "postgres://fixture", PGSSLMODE: "require" });
  const development = loadKaarya(source, {
    DATABASE_URL: "postgres://fixture",
    NODE_ENV: "development",
  });
  const queryResult = await production.exports.query("SELECT $1", ["fixture"]);
  const client = await production.exports.getClient();
  return {
    productionSecure: secureTlsOptions(production.pool.options.ssl),
    requiredModeSecure: secureTlsOptions(required.pool.options.ssl),
    developmentModePreserved: development.pool.options.ssl === false,
    poolContractPreserved:
      production.pool.options.connectionString === "postgres://fixture" &&
      production.pool.options.max === 20 &&
      production.pool.options.idleTimeoutMillis === 30000 &&
      production.pool.options.connectionTimeoutMillis === 5000,
    queryContractPreserved:
      queryResult?.rows?.[0]?.id === 1 &&
      production.pool.queries[0]?.text === "SELECT $1" &&
      production.pool.queries[0]?.params?.[0] === "fixture",
    clientContractPreserved: client === production.pool.client,
  };
}

function loadKubex(source, databaseUrl) {
  PoolFixture.instances = [];
  const exports = loadModule(
    source,
    "services/mcp-server/src/clients/postgres.ts",
    (specifier) => {
      if (specifier === "pg") return { __esModule: true, default: { Pool: PoolFixture } };
      if (specifier === "node:fs")
        return { __esModule: true, default: { readFileSync: () => "fixture-ca" } };
      if (specifier === "node:path") return { __esModule: true, default: path.posix };
      if (specifier === "node:url") {
        return { fileURLToPath: (value) => new URL(value).pathname };
      }
      return universalStub();
    },
    { DATABASE_URL: databaseUrl },
  );
  return { exports, pool: PoolFixture.instances[0] };
}

async function observeKubex(files) {
  const source = files["services/mcp-server/src/clients/postgres.ts"];
  const supabase = loadKubex(source, "postgres://fixture.supabase.co/database");
  const local = loadKubex(source, "postgres://localhost/database");
  const rows = await supabase.exports.query("SELECT $1", ["fixture"]);
  const one = await supabase.exports.queryOne("SELECT 1");
  await supabase.exports.testConnection();
  await supabase.exports.shutdown();
  return {
    supabaseSecure:
      secureTlsOptions(supabase.pool.options.ssl) &&
      typeof supabase.pool.options.ssl.ca === "string" &&
      supabase.pool.options.ssl.ca.length > 0,
    localModePreserved: local.pool.options.ssl === undefined,
    poolContractPreserved:
      supabase.pool.options.connectionString.includes("supabase") &&
      supabase.pool.options.max === 10,
    queryContractPreserved: rows?.[0]?.id === 1 && one?.id === 1,
    lifecyclePreserved: supabase.pool.client.released === true && supabase.pool.ended === true,
  };
}

async function observeLibmongocrypt(files) {
  const source = files["bindings/node/lib/stateMachine.js"];
  const connections = [];
  class BufferListFixture {
    constructor() {
      this.buffer = Buffer.alloc(0);
    }
    append(value) {
      this.buffer = Buffer.concat([this.buffer, Buffer.from(value)]);
    }
    get length() {
      return this.buffer.length;
    }
    slice(start, end) {
      return this.buffer.slice(start, end);
    }
    consume(count) {
      this.buffer = this.buffer.slice(count);
    }
  }
  const tls = {
    connect(options, callback) {
      const socket = new EventEmitter();
      socket.writes = [];
      socket.write = (value) => socket.writes.push(Buffer.from(value));
      socket.destroy = () => {
        socket.destroyed = true;
      };
      socket.end = (done) => {
        socket.ended = true;
        done?.();
      };
      connections.push({ options, socket });
      queueMicrotask(callback);
      return socket;
    },
  };
  class MongoCryptError extends Error {}
  const customRequire = (specifier) => {
    if (specifier === "tls") return tls;
    if (specifier === "bl") return BufferListFixture;
    if (specifier === "./common") {
      return { debug() {}, databaseNamespace() {}, collectionNamespace() {}, MongoCryptError };
    }
    return universalStub();
  };
  const factory = loadModule(source, "bindings/node/lib/stateMachine.js", customRequire);
  const { StateMachine } = factory({ mongodb: { MongoTimeoutError: class extends Error {} } });
  const machine = new StateMachine({ bson: {} });
  const request = {
    endpoint: "kms.example:8443",
    message: Buffer.from("fixture-request"),
    bytesNeeded: 1,
    addResponse(value) {
      this.bytesNeeded -= value.length;
    },
  };
  const promise = machine.kmsRequest(request);
  await new Promise((resolve) => setImmediate(resolve));
  const connection = connections[0];
  connection?.socket.emit("data", Buffer.from("x"));
  await promise;
  return {
    verificationEnabled: secureTlsOptions(connection?.options),
    hostnameVerificationEnabled: connection?.options?.servername === "kms.example",
    endpointAndPortPreserved:
      connection?.options?.host === "kms.example" && connection.options.port === 8443,
    requestWritePreserved: connection?.socket.writes[0]?.toString() === "fixture-request",
    responseLifecyclePreserved: request.bytesNeeded === 0 && connection?.socket.ended === true,
    timeoutHandlerPreserved: connection?.socket.listenerCount("timeout") === 1,
  };
}

function observeNodeSass(files) {
  const source = files["scripts/util/downloadoptions.js"];
  function invoke(proxy) {
    const exported = loadModule(source, "scripts/util/downloadoptions.js", (specifier) => {
      if (specifier === "./proxy") return () => proxy;
      if (specifier === "./useragent") return () => "fixture-agent";
      if (specifier === "./rejectUnauthorized") return () => true;
      return universalStub();
    });
    return exported();
  }
  const direct = invoke(null);
  const proxied = invoke("http://proxy.example");
  return {
    secureDefault: direct.rejectUnauthorized !== false,
    timeoutPreserved: direct.timeout === 60000,
    requestShapePreserved:
      direct.headers?.["User-Agent"] === "fixture-agent" && direct.encoding === null,
    proxyPreserved: proxied.proxy === "http://proxy.example" && !Object.hasOwn(direct, "proxy"),
  };
}

function expressionValue(node, constants) {
  if (!node) return undefined;
  if (node.kind === ts.SyntaxKind.TrueKeyword) return true;
  if (node.kind === ts.SyntaxKind.FalseKeyword) return false;
  if (ts.isParenthesizedExpression(node)) return expressionValue(node.expression, constants);
  if (ts.isIdentifier(node)) return constants.get(node.text);
  if (ts.isStringLiteralLike(node) || ts.isNumericLiteral(node)) return node.text;
  if (ts.isPrefixUnaryExpression(node) && node.operator === ts.SyntaxKind.ExclamationToken) {
    const value = expressionValue(node.operand, constants);
    return value === undefined ? undefined : !value;
  }
  if (ts.isBinaryExpression(node)) {
    const left = expressionValue(node.left, constants);
    const right = expressionValue(node.right, constants);
    if (node.operatorToken.kind === ts.SyntaxKind.QuestionQuestionToken) return left ?? right;
    if (node.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken) return left && right;
    if (node.operatorToken.kind === ts.SyntaxKind.BarBarToken) return left || right;
  }
  return undefined;
}

function objectProperty(object, name) {
  if (!ts.isObjectLiteralExpression(object)) return null;
  return (
    object.properties.find(
      (property) =>
        ts.isPropertyAssignment(property) &&
        (property.name?.text === name || property.name?.escapedText === name),
    ) ?? null
  );
}

function observeOobee(files) {
  const source = files["public/electron/main.js"];
  const tree = ts.createSourceFile(
    "main.js",
    source,
    ts.ScriptTarget.ES2022,
    true,
    ts.ScriptKind.JS,
  );
  const constants = new Map();
  const initializers = new Map();
  const axiosOptionsByClient = new Map();
  const clientsUsedForGet = new Set();
  function visit(node) {
    if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) {
      initializers.set(node.name.text, node.initializer);
      const value = expressionValue(node.initializer, constants);
      if (value !== undefined) constants.set(node.name.text, value);
      if (
        ts.isCallExpression(node.initializer) &&
        ts.isPropertyAccessExpression(node.initializer.expression) &&
        node.initializer.expression.expression.getText(tree) === "axios" &&
        node.initializer.expression.name.text === "create" &&
        node.initializer.arguments[0]
      ) {
        axiosOptionsByClient.set(node.name.text, node.initializer.arguments[0]);
      }
    }
    if (
      ts.isCallExpression(node) &&
      ts.isPropertyAccessExpression(node.expression) &&
      node.expression.name.text === "get" &&
      ts.isIdentifier(node.expression.expression)
    ) {
      clientsUsedForGet.add(node.expression.expression.text);
    }
    ts.forEachChild(node, visit);
  }
  visit(tree);
  const updaterClients = [...clientsUsedForGet].filter((name) => axiosOptionsByClient.has(name));
  const axiosOptions =
    updaterClients.length === 1 ? axiosOptionsByClient.get(updaterClients[0]) : null;
  const agentProperty = axiosOptions ? objectProperty(axiosOptions, "httpsAgent") : null;
  let agentExpression = agentProperty?.initializer ?? null;
  if (agentExpression && ts.isIdentifier(agentExpression)) {
    agentExpression = initializers.get(agentExpression.text) ?? null;
  }
  const agentOptions =
    agentExpression &&
    ts.isNewExpression(agentExpression) &&
    ts.isPropertyAccessExpression(agentExpression.expression) &&
    agentExpression.expression.name.text === "Agent"
      ? (agentExpression.arguments?.[0] ?? null)
      : null;
  const rejectProperty = agentOptions ? objectProperty(agentOptions, "rejectUnauthorized") : null;
  const timeoutProperty = axiosOptions ? objectProperty(axiosOptions, "timeout") : null;
  const executableSource = stripCStyleComments(source);
  const insecureGlobal =
    /NODE_TLS_REJECT_UNAUTHORIZED\s*\]\s*=\s*['"]?0/.test(executableSource) ||
    /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/.test(executableSource) ||
    /appendSwitch\(\s*['"]ignore-certificate-errors['"]/.test(executableSource);
  return {
    globalVerificationPreserved: !insecureGlobal,
    updaterVerificationEnabled:
      axiosOptions !== null &&
      (agentProperty === null ||
        (agentOptions !== null &&
          (!rejectProperty || expressionValue(rejectProperty.initializer, constants) === true))),
    updaterTimeoutPreserved:
      timeoutProperty !== null &&
      expressionValue(timeoutProperty.initializer, constants) === "5000",
    applicationLifecyclePreserved:
      /app\.on\(\s*['"]ready['"]/.test(executableSource) &&
      /new\s+BrowserWindow\s*\(/.test(executableSource) &&
      /mainWindow\.loadFile/.test(executableSource),
  };
}

function loadStreetlives(source, environment) {
  return loadModule(
    source,
    "src/config.js",
    (specifier) => {
      if (specifier === "./utils/strings") {
        return {
          parseBoolean: (value, fallback) => (value === undefined ? fallback : value === "true"),
          parseNumber: (value, fallback) => (value === undefined ? fallback : Number(value)),
        };
      }
      if (specifier === "node:fs" || specifier === "fs") {
        return { readFileSync: () => "fixture-ca" };
      }
      return universalStub();
    },
    environment,
  ).default;
}

function observeStreetlives(files) {
  const source = files["src/config.js"];
  const production = loadStreetlives(source, {
    NODE_ENV: "production",
    DATABASE_SSL_CA: "line-one\\nline-two",
  });
  const test = loadStreetlives(source, { NODE_ENV: "test" });
  const ssl = production?.db?.options?.dialectOptions?.ssl;
  return {
    productionSecure: secureTlsOptions(ssl) && ssl.require === true,
    customTrustPreserved: ssl?.ca === "line-one\nline-two" || ssl?.ca === "fixture-ca",
    testModePreserved: test?.db?.options?.dialectOptions?.ssl === undefined,
    databaseDefaultsPreserved:
      production?.db?.database === "streetlives" &&
      production?.db?.options?.dialect === "postgres" &&
      production?.db?.options?.port === 5432 &&
      production?.db?.options?.pool?.max === 1,
  };
}

const contracts = {
  "alist-ldap-tls-verification": {
    observe: observeAlist,
    acceptance: [
      ["LDAP TLS is secure by default", "secureDefault"],
      ["Configured default is bound safely", "configuredDefaultBound"],
    ],
    regressions: [
      ["LDAPS dialing remains available", "ldapsPreserved"],
      ["Plain LDAP dialing remains available", "ldapPreserved"],
    ],
  },
  "bigflow-deploy-tls-verification": {
    observe: observeBigflow,
    acceptance: [["Vault requests verify TLS", "secureDefault"]],
    regressions: [
      ["Vault endpoint is preserved", "endpointPreserved"],
      ["Vault token header is preserved", "secretHeaderPreserved"],
      ["Vault token response is preserved", "tokenResponsePreserved"],
      ["Missing credentials remain rejected", "missingInputsRejected"],
    ],
  },
  "blackduck-client-tls-verification": {
    observe: observeBlackduck,
    acceptance: [
      ["Scan uploads verify TLS", "secureUploads"],
      ["Scan downloads verify TLS", "secureDownloads"],
    ],
    regressions: [
      ["Explicit insecure compatibility mode remains scoped", "explicitInsecureModePreserved"],
      ["Upload media types remain correct", "uploadFormatsPreserved"],
      ["Downloaded bytes remain intact", "downloadBodyPreserved"],
    ],
  },
  "css-parser-http-tls-verification": {
    observe: observeCssParser,
    acceptance: [["HTTPS certificate verification is enabled", "verificationEnabled"]],
    regressions: [
      ["HTTPS requests remain enabled", "httpsPreserved"],
      ["Remote GET remains available", "requestPreserved"],
      ["Redirect and compression handling remain available", "redirectAndCompressionPreserved"],
    ],
  },
  "gobot-mqtt-tls-verification": {
    observe: observeGobot,
    acceptance: [["MQTT certificate verification is enabled", "verificationEnabled"]],
    regressions: [
      ["MQTT TLS path remains available", "tlsPathPreserved"],
      ["Server trust configuration remains available", "serverTrustPreserved"],
      ["Client certificates remain available", "clientCertificatesPreserved"],
    ],
  },
  "graphql-tools-websocket-tls-verification": {
    observe: observeGraphql,
    acceptance: [["WebSocket TLS is secure by default", "secureDefault"]],
    regressions: [
      ["Endpoint and protocol remain intact", "endpointAndProtocolPreserved"],
      ["WebSocket behavior options remain intact", "websocketOptionsPreserved"],
      ["Custom headers remain intact", "headersPreserved"],
    ],
  },
  "kaarya-postgres-tls-verification": {
    observe: observeKaarya,
    acceptance: [
      ["Production PostgreSQL verifies TLS", "productionSecure"],
      ["Required SSL mode verifies TLS", "requiredModeSecure"],
    ],
    regressions: [
      ["Local development mode remains available", "developmentModePreserved"],
      ["Pool settings remain intact", "poolContractPreserved"],
      ["Query behavior remains intact", "queryContractPreserved"],
      ["Dedicated clients remain available", "clientContractPreserved"],
    ],
  },
  "kubex-postgres-tls-verification": {
    observe: observeKubex,
    acceptance: [["Supabase PostgreSQL verifies its trusted certificate", "supabaseSecure"]],
    regressions: [
      ["Local non-TLS mode remains available", "localModePreserved"],
      ["Pool settings remain intact", "poolContractPreserved"],
      ["Query helpers remain intact", "queryContractPreserved"],
      ["Connection lifecycle remains intact", "lifecyclePreserved"],
    ],
  },
  "libmongocrypt-kms-tls-verification": {
    observe: observeLibmongocrypt,
    acceptance: [
      ["KMS TLS verification is enabled", "verificationEnabled"],
      ["KMS hostname verification is enabled", "hostnameVerificationEnabled"],
    ],
    regressions: [
      ["KMS endpoint and port remain intact", "endpointAndPortPreserved"],
      ["KMS request bytes remain intact", "requestWritePreserved"],
      ["KMS response lifecycle remains intact", "responseLifecyclePreserved"],
      ["KMS timeout handling remains intact", "timeoutHandlerPreserved"],
    ],
  },
  "node-sass-download-tls-verification": {
    observe: observeNodeSass,
    acceptance: [["Binary downloads verify TLS by default", "secureDefault"]],
    regressions: [
      ["Download timeout remains intact", "timeoutPreserved"],
      ["Request headers and binary encoding remain intact", "requestShapePreserved"],
      ["Proxy support remains intact", "proxyPreserved"],
    ],
  },
  "oobee-updater-tls-verification": {
    observe: observeOobee,
    acceptance: [
      ["Process-wide TLS verification remains enabled", "globalVerificationPreserved"],
      ["Updater TLS verification is enabled", "updaterVerificationEnabled"],
    ],
    regressions: [
      ["Updater timeout remains intact", "updaterTimeoutPreserved"],
      ["Electron application lifecycle remains intact", "applicationLifecyclePreserved"],
    ],
  },
  "streetlives-rds-tls-verification": {
    observe: observeStreetlives,
    acceptance: [
      ["Production RDS verifies TLS", "productionSecure"],
      ["Configured RDS trust is preserved", "customTrustPreserved"],
    ],
    regressions: [
      ["Test database mode remains available", "testModePreserved"],
      ["Database defaults remain intact", "databaseDefaultsPreserved"],
    ],
  },
};

export async function gradeTlsCandidate(id, files) {
  const contract = contracts[id];
  if (!contract) throw new Error(`Unsupported TLS case: ${id}`);
  try {
    const observed = await contract.observe(files);
    return result(observed, contract.acceptance, contract.regressions);
  } catch (error) {
    const keys = [...contract.acceptance, ...contract.regressions].map(([, key]) => key);
    const observed = Object.fromEntries(keys.map((key) => [key, false]));
    return result(
      observed,
      contract.acceptance,
      contract.regressions,
      `${error.name}: ${error.message}`,
    );
  }
}

export const tlsCaseIds = Object.freeze(Object.keys(contracts));
