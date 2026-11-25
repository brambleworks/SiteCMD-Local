#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  candidateHistoryShapeFailures,
  ENGINE_CRATES,
  ENGINE_RUST_CRATES,
  enginePathFailures,
  publicationHistoryPathFailures,
} from "./lib/publication-history-rules.mjs";
import { tomlFields, tomlText } from "./lib/toml-fields.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const PUBLISHED_MOVES = "tools/scripts/published-engine-moves.json";
const PATHSPEC_ENV = [
  "GIT_LITERAL_PATHSPECS",
  "GIT_GLOB_PATHSPECS",
  "GIT_NOGLOB_PATHSPECS",
  "GIT_ICASE_PATHSPECS",
];
const OID = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const NO_OBJECT = /^0+$/;
const nonempty = (value, separator = "\n") => value.split(separator).filter(Boolean);
const RUST_CRATE_WORD = "(^|[^[:alnum:]_])(" + ENGINE_RUST_CRATES.join("|") + ")([^[:alnum:]_]|$)";
const CARGO_CRATE_WORDS = ENGINE_CRATES.map((name) => [
  name,
  new RegExp("(?<![\\w-])" + name + "(?![\\w-])"),
]);
const CARGO_FILE_NAMES = ["cargo.toml", "cargo.lock"];
const CARGO_CONFIG_DIRECTORY = ".cargo";
const RUST_SCAN_SUFFIX = ".rs";

const PRIVATE_PATH = /^\/*brambleworks\/+SiteCMD-Engine(?:\.git)?\/*$/i;
const PRIVATE_HOSTS = new Set(["github.com", "ssh.github.com"]);
const NETWORK_SCHEME = /^(?:https?|git|ssh|git\+ssh|ssh\+git):\/\//i;
const SCP_USER = /^[^@/:\s]+@/;
const SCP_HOST_PATH = /^(?<host>[^@:/?#\s]+):(?!\/\/)(?<path>.*)$/s;

function transportPrefixLength(url) {
  const prefix = /[a-z][a-z\d+.-]*::/iy;
  let end = 0;
  while (prefix.test(url)) end = prefix.lastIndex;
  return end;
}

function networkDestination(address) {
  const scheme = NETWORK_SCHEME.exec(address)?.[0];
  if (!scheme) return;
  const slash = address.indexOf("/", scheme.length);
  if (slash === -1) return;
  const authority = address.slice(scheme.length, slash);
  if (/[?#\s]/.test(authority)) return;
  const hostPort = authority.slice(authority.lastIndexOf("@") + 1);
  const colon = hostPort.indexOf(":");
  const host = colon === -1 ? hostPort : hostPort.slice(0, colon);
  if (!host || (colon !== -1 && !/^\d+$/.test(hostPort.slice(colon + 1)))) return;
  return { host, path: address.slice(slash + 1) };
}

function parseDestination(address) {
  return networkDestination(address) ?? address.replace(SCP_USER, "").match(SCP_HOST_PATH)?.groups;
}

function isPrivateDestination(url) {
  // Only an exact ASCII spelling skips: no percent-encoding, whitespace or
  // brackets, which git reads as a bracketed host inside the authority.
  if (/[^!-~]|[%[\]]/.test(url)) return false;
  const address = url.slice(transportPrefixLength(url));
  const destination = parseDestination(address);
  if (!destination) return false;
  // Over HTTP a query or fragment never reaches the repository path; ssh and git
  // send the raw path, so there a query or fragment is checked, never skipped.
  const http = /^https?:\/\//i.test(address);
  if (!http && /[?#]/.test(destination.path)) return false;
  const repositoryPath = http ? destination.path.split(/[?#]/, 1)[0] : destination.path;
  return PRIVATE_HOSTS.has(destination.host.toLowerCase()) && PRIVATE_PATH.test(repositoryPath);
}

function redactedDestination(url) {
  const prefixLength = transportPrefixLength(url);
  const address = url
    .slice(prefixLength)
    .replace(/^([a-z][a-z\d+.-]*:\/\/)[^/?#\s]*@/i, "$1***@")
    .replace(/^[^@/:\s]+@(?=(?:\[[^\]\s]+\]|[^@/:\s]+):)/, "***@")
    .replace(/\?.*/s, "?***");
  return url.slice(0, prefixLength) + address;
}

function git(
  args,
  { cwd = ROOT, env = process.env, input, allowMissing = false, redact = false } = {},
) {
  const gitEnv = { ...env };
  for (const key of PATHSPEC_ENV) delete gitEnv[key];
  delete gitEnv.GIT_WORK_TREE;
  const result = spawnSync("git", args, {
    cwd,
    env: gitEnv,
    input,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    stdio: [input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
  });
  const grepError = args[0] === "grep" && Boolean(result.stderr?.trim());
  if (allowMissing && result.status === 1 && !grepError) return null;
  if (result.status !== 0 || grepError) {
    const exit =
      result.error?.code ?? (grepError ? "scan reported an error" : `exit ${result.status}`);
    const detail = redact ? exit : result.stderr?.trim() || result.stdout?.trim() || exit;
    throw new Error(`git ${args[0]} failed: ${detail}`);
  }
  return result.stdout;
}

function treeEntries(runGit, tree) {
  return nonempty(runGit(["ls-tree", "-rz", "--full-tree", tree]), "\0").map((record) => {
    const tab = record.indexOf("\t");
    const [mode, type, oid] = record.slice(0, tab).split(" ");
    return { file: record.slice(tab + 1), mode, type, oid };
  });
}

function scanFileFailures(runGit, commit, pathspecs, pattern, failuresIn) {
  const matches = runGit(
    [
      "grep",
      "--full-name",
      "--no-color",
      "--text",
      "-zlE",
      "-e",
      pattern,
      commit,
      "--",
      ...pathspecs,
    ],
    { allowMissing: true },
  );
  return nonempty(matches ?? "", "\0").flatMap((entry) => {
    const file = entry.slice(commit.length + 1);
    const source = runGit(["cat-file", "blob", entry]);
    return failuresIn(source, file);
  });
}

function crateNameFailures(file, names) {
  return names.map(
    (name) => `${JSON.stringify(file)} names the private crate ${name}. Remove that reference.`,
  );
}

function cargoFileFailures(source, file) {
  const fields = tomlFields(source);
  const parts = fields.flatMap(({ path, value }) => [
    ...path,
    ...(Array.isArray(value) ? value.map(tomlText) : [value]),
  ]);
  const names = CARGO_CRATE_WORDS.filter(
    ([, pattern]) => pattern.test(source) || parts.some((part) => pattern.test(part)),
  ).map(([name]) => name);
  return [...crateNameFailures(file, names), ...cargoIncludeFailures(file, fields)];
}

function cargoIncludeFailures(file, fields) {
  const directories = file.toLowerCase().split("/").slice(0, -1);
  const cargoIndex = directories.lastIndexOf(CARGO_CONFIG_DIRECTORY);
  if (cargoIndex === -1) return [];
  const depth = directories.length - cargoIndex - 1;
  for (const { path: keys, value } of fields) {
    if (keys[0] !== "include" || !(keys.length === 1 || (keys.length === 2 && keys[1] === "path")))
      continue;
    const includes = Array.isArray(value)
      ? value
          .filter((token, index) => /^["']/.test(token) && value[index + 1] !== "=")
          .map(tomlText)
      : [value];
    if (includes.some((target) => leavesCargoDirectory(target, depth))) {
      return [
        `${JSON.stringify(file)} includes a file outside its .cargo directory. Remove that include.`,
      ];
    }
  }
  return [];
}

function leavesCargoDirectory(target, depth) {
  if (/^(?:[\\/]|[a-z]:)/i.test(target)) return true;
  // Traversing outside .cargo can follow a symlink before later segments return.
  return [target.split("/"), target.split(/[\\/]/)].some((segments) => {
    let remaining = depth;
    for (const segment of segments) {
      if (segment === "..") {
        if (remaining === 0) return true;
        remaining--;
      } else if (segment !== "" && segment !== ".") {
        remaining++;
      }
    }
    return false;
  });
}

function rustFileFailures(source, file) {
  const names = ENGINE_RUST_CRATES.filter((name) => new RegExp("\\b" + name + "\\b").test(source));
  return crateNameFailures(file, names);
}

function privateBlobIds(runGit) {
  const clone = runGit(["config", "--null", "--path", "--get", "sitecmd.privateClone"], {
    allowMissing: true,
  });
  if (clone === null) return new Set();
  const clonePath = clone.slice(0, -1);
  if (!clonePath) throw new Error("Set sitecmd.privateClone to a Git clone path or unset it.");

  const env = { ...process.env };
  for (const key of nonempty(runGit(["rev-parse", "--local-env-vars"]))) delete env[key];
  env.GIT_NO_REPLACE_OBJECTS = "1";
  env.GIT_NO_LAZY_FETCH = "1";
  const privateGit = (args) => {
    try {
      return git(args, { cwd: path.resolve(ROOT, clonePath), env, redact: true });
    } catch (error) {
      throw new Error(
        "Could not read sitecmd.privateClone at " +
          JSON.stringify(clonePath) +
          ": " +
          error.message,
        { cause: error },
      );
    }
  };
  const blobs = new Set();
  let foundEnginePath = false;
  for (const tree of new Set(nonempty(privateGit(["log", "--format=%T", "--branches"])))) {
    const entries = treeEntries(privateGit, tree);
    const denied = new Set(enginePathFailures(entries.map(({ file }) => file)));
    if (denied.size > 0) foundEnginePath = true;
    for (const { file, type, oid } of entries) {
      if (type === "blob" && denied.has(file)) blobs.add(oid);
    }
  }
  if (!foundEnginePath) {
    throw new Error(
      `No private engine paths found in sitecmd.privateClone at ${JSON.stringify(clonePath)}.`,
    );
  }
  return blobs;
}

function publicRefTips(runGit, url, remoteTips) {
  let refs;
  try {
    const resolved = runGit(["ls-remote", "--get-url", "--", url]).replace(/\n$/, "");
    if (resolved !== url) return [...new Set(remoteTips)];
    refs = runGit(["ls-remote", "--refs", "--", url]);
  } catch (error) {
    throw new Error(
      `Could not read refs from ${JSON.stringify(redactedDestination(url))}: ${error.message}`,
      { cause: error },
    );
  }
  const serverTips = nonempty(refs).map((line) => line.split("\t", 1)[0]);
  return [...new Set([...remoteTips, ...serverTips.filter((oid) => OID.test(oid))])];
}

function privateBlobsNotPublic(runGit, publicTips) {
  const blobIds = privateBlobIds(runGit);
  if (blobIds.size > 0 && publicTips.length > 0) {
    const reachable = runGit(
      [
        "rev-list",
        "--objects",
        "--no-object-names",
        "--ignore-missing",
        "--missing=print",
        "--stdin",
      ],
      { input: publicTips.join("\n") + "\n", noLazyFetch: true },
    );
    for (const oid of nonempty(reachable)) blobIds.delete(oid.replace(/^\?/, ""));
  }
  return blobIds;
}

function isCrateScanPath(file) {
  const lower = file.toLowerCase();
  const segments = lower.split("/");
  return (
    lower.endsWith(RUST_SCAN_SUFFIX) ||
    CARGO_FILE_NAMES.includes(segments.at(-1)) ||
    segments.includes(CARGO_CONFIG_DIRECTORY)
  );
}

function treeBoundaryFailures(runGit, commit, entries) {
  return [
    ...enginePathFailures(entries.map(({ file }) => file)).map(
      (file) => `${JSON.stringify(file)} is a private engine path. Remove that path.`,
    ),
    ...entries
      .filter(({ file, mode }) => mode === "120000" && isCrateScanPath(file))
      .map(({ file }) => `${JSON.stringify(file)} is a symbolic link. Remove that link.`),
    ...scanFileFailures(
      runGit,
      commit,
      [...CARGO_FILE_NAMES, CARGO_CONFIG_DIRECTORY + "/**"].map(
        (name) => `:(top,icase,glob)**/${name}`,
      ),
      "^",
      cargoFileFailures,
    ),
    ...scanFileFailures(
      runGit,
      commit,
      [`:(top,icase,glob)**/*${RUST_SCAN_SUFFIX}`],
      RUST_CRATE_WORD,
      rustFileFailures,
    ),
  ];
}

/** Refuses a repeated key in any object of the list, where JSON.parse keeps the last one. */
function requireUniqueMoveListKeys(source) {
  // One key set per open object; arrays hold null so their colons never count.
  const open = [];
  let previous;
  for (const [token] of source.matchAll(/"(?:\\.|[^"\\])*"|[{}[\]:]/g)) {
    if (token === "{") open.push(new Set());
    if (token === "[") open.push(null);
    if (token === "}" || token === "]") open.pop();
    const keys = open.at(-1);
    if (token === ":" && keys) {
      const key = JSON.parse(previous);
      if (keys.has(key)) {
        throw new Error(
          open.length === 1
            ? `duplicate top-level key ${JSON.stringify(key)}`
            : `duplicate key ${JSON.stringify(key)} in an entry`,
        );
      }
      keys.add(key);
    }
    previous = token;
  }
}

function publishedMoves(runGit, commit, entries) {
  const moves = new Map();
  const entry = entries.find(({ file }) => file === PUBLISHED_MOVES);
  if (!entry) return moves;
  try {
    if (entry.type !== "blob" || !entry.mode.startsWith("100")) {
      throw new Error("expected a regular file");
    }
    const source = runGit(["cat-file", "blob", `${commit}:${PUBLISHED_MOVES}`]);
    const list = JSON.parse(source);
    requireUniqueMoveListKeys(source);
    if (typeof list?.approved !== "string" || !list.approved.trim() || !Array.isArray(list.moves)) {
      throw new Error("expected an approved statement and a moves array");
    }
    for (const [index, entry] of list.moves.entries()) {
      const { path: file, blob } = entry ?? {};
      if (
        typeof file !== "string" ||
        file.split("/").some((part) => ["", ".", ".."].includes(part))
      ) {
        throw new Error(`entry ${index + 1} requires a repository-relative path`);
      }
      if (typeof blob !== "string" || !OID.test(blob)) {
        throw new Error(`entry ${index + 1} requires a blob object ID`);
      }
      if (moves.has(file)) throw new Error(`duplicate path ${JSON.stringify(file)}`);
      moves.set(file, blob);
    }
  } catch (error) {
    throw new Error(`Malformed ${PUBLISHED_MOVES} in commit ${commit}: ${error.message}`, {
      cause: error,
    });
  }
  return moves;
}

function checkPublicTrees(runGit, commits, privateBlobs = new Set()) {
  let rejected = false;
  for (const commit of commits) {
    const entries = treeEntries(runGit, commit);
    const moves = publishedMoves(runGit, commit, entries);
    const failures = treeBoundaryFailures(runGit, commit, entries);
    for (const { file, type, oid } of entries) {
      if (type === "blob" && privateBlobs.has(oid) && moves.get(file) !== oid) {
        failures.push(`${JSON.stringify(file)} matches a private engine blob. Remove that file.`);
      }
    }
    for (const failure of failures) {
      process.stderr.write(
        `Commit ${commit}: ${failure} Rewrite the outgoing commits before publishing.\n`,
      );
      rejected = true;
    }
  }
  return rejected ? 1 : 0;
}

function pushUpdates(input) {
  return nonempty(input.trim()).map((line) => {
    const [localRef, local, remoteRef, remote, extra] = line.trim().split(/\s+/);
    if (
      !OID.test(local ?? "") ||
      !OID.test(remote ?? "") ||
      local.length !== remote.length ||
      !remoteRef.startsWith("refs/") ||
      remoteRef === "refs/" ||
      (localRef === "(delete)") !== NO_OBJECT.test(local) ||
      extra !== undefined
    ) {
      throw new Error("Invalid pre-push ref update.");
    }
    return { local, remote };
  });
}

function checkPublicHistory(mode, args) {
  const env = { ...process.env, GIT_NO_REPLACE_OBJECTS: "1" };
  delete env.GIT_NO_LAZY_FETCH;
  const runGit = (command, { noLazyFetch, ...options } = {}) =>
    git(command, {
      ...options,
      env: noLazyFetch ? { ...env, GIT_NO_LAZY_FETCH: "1" } : env,
      redact: true,
    });
  if (mode === "--pre-push") {
    const [, url = ""] = args;
    if (isPrivateDestination(url)) return 0;
    const updates = pushUpdates(readFileSync(0, "utf8"));
    const localTips = new Set(
      updates.map(({ local }) => local).filter((oid) => !NO_OBJECT.test(oid)),
    );
    if (localTips.size === 0) return 0;
    const tips = new Set();
    for (const oid of localTips) {
      const commit = runGit(["rev-parse", "--verify", "--quiet", oid + "^{commit}"], {
        allowMissing: true,
      });
      if (commit === null) throw new Error("Pushed object " + oid + " does not point to a commit.");
      tips.add(commit.trim());
    }
    const remoteTips = updates.map(({ remote }) => remote).filter((oid) => !NO_OBJECT.test(oid));
    const publicTips = publicRefTips(runGit, url, remoteTips);
    const commits = nonempty(
      runGit(["rev-list", "--ignore-missing", "--stdin"], {
        input: [...tips, ...publicTips.map((oid) => "^" + oid)].join("\n") + "\n",
      }),
    );
    return checkPublicTrees(runGit, commits, privateBlobsNotPublic(runGit, publicTips));
  }

  const [base, head] = args;
  if (args.length !== 2 || !OID.test(base) || !OID.test(head)) {
    throw new Error("Use --pull-request with the base and head commit IDs.");
  }
  return checkPublicTrees(runGit, nonempty(runGit(["rev-list", `${base}..${head}`])));
}

const arguments_ = process.argv.slice(2).filter((argument) => argument !== "--");
const requestedScope = arguments_[0] ?? "--all";
if (requestedScope === "--pre-push" || requestedScope === "--pull-request") {
  try {
    process.exit(checkPublicHistory(requestedScope, arguments_.slice(1)));
  } catch (error) {
    process.stderr.write(`Public tree check failed: ${error.message}\n`);
    process.exit(2);
  }
}
if (arguments_.length > 1) {
  process.stderr.write(
    "Publication history check failed: use --all, --candidate-main, or one Git ref.\n",
  );
  process.exit(2);
}
const scanAllRefs = requestedScope === "--all";
const candidateMain = requestedScope === "--candidate-main";
const requestedRef = candidateMain ? "refs/heads/main" : requestedScope;

let commit;
try {
  commit = scanAllRefs ? null : git(["rev-parse", "--verify", `${requestedRef}^{commit}`]).trim();
} catch (error) {
  process.stderr.write(`Publication history check failed: ${error.message}\n`);
  process.exit(2);
}

const revisionArgs = scanAllRefs ? ["--all", "HEAD"] : [commit];
const paths = git(["log", "--format=", "--name-only", ...revisionArgs])
  .split("\n")
  .map((value) => value.trim())
  .filter(Boolean);
const pathFailures = publicationHistoryPathFailures(paths);
const shapeFailures = candidateMain
  ? candidateHistoryShapeFailures(
      git(["rev-list", "--count", commit]).trim(),
      git(["rev-list", "--parents", "--max-count=1", commit]).trim(),
    )
  : [];

const gitleaks = spawnSync(
  "gitleaks",
  [
    "git",
    "--redact",
    "--no-banner",
    "--config=.gitleaks.toml",
    `--log-opts=${scanAllRefs ? "--all HEAD" : commit}`,
  ],
  {
    cwd: ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  },
);

if (gitleaks.error?.code === "ENOENT") {
  process.stderr.write(
    "Publication history check failed: the Gitleaks CLI is required to scan every reachable commit. Install it as documented in README.md.\n",
  );
  process.exit(2);
}

const secretScanFailed = gitleaks.status !== 0;
if (pathFailures.length > 0 || shapeFailures.length > 0 || secretScanFailed) {
  const scope = scanAllRefs
    ? "all refs"
    : `${candidateMain ? "candidate main" : requestedRef} (${commit.slice(0, 12)})`;
  process.stderr.write(`Publication history failed for ${scope}:\n`);
  for (const failure of pathFailures) process.stderr.write(`- ${failure}\n`);
  for (const failure of shapeFailures) process.stderr.write(`- ${failure}\n`);
  if (secretScanFailed) {
    process.stderr.write("- gitleaks found secret-like material in reachable history\n");
    const redactedOutput = `${gitleaks.stdout ?? ""}${gitleaks.stderr ?? ""}`.trim();
    if (redactedOutput) process.stderr.write(`${redactedOutput}\n`);
  }
  process.exit(1);
}

const scope = scanAllRefs
  ? "all refs"
  : `${candidateMain ? "candidate main" : requestedRef} (${commit.slice(0, 12)})`;
process.stdout.write(
  `Publication history passed for ${scope} (${new Set(paths).size} historical paths checked).\n`,
);
