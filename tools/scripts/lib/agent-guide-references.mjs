import { execFileSync } from "node:child_process";
import fs from "node:fs";
import { posix as path } from "node:path";
import { guideTriggers, markdownAnchors, markdownParts } from "./agent-guide-markdown.mjs";

const INLINE_CODE = /(`+)([^`\n]+)\1/g;
const EXTERNAL = /^(?:[a-z][\w+.-]*:|\/\/)/i;
const GLOB = /[*?[]|\{[^}]+(?:,|\.\.)[^}]+\}/;
const PNPM_BUILT_INS = new Set([
  "add",
  "audit",
  "create",
  "dlx",
  "exec",
  "fetch",
  "help",
  "init",
  "install",
  "list",
  "outdated",
  "pack",
  "patch",
  "publish",
  "rebuild",
  "remove",
  "run",
  "setup",
  "store",
  "unlink",
  "update",
  "why",
]);

export function guidePath(guide, reference) {
  return reference.startsWith("/")
    ? path.normalize(reference).slice(1)
    : path.join(path.dirname(guide), reference);
}

function isFile(file) {
  return fs.existsSync(file) && fs.statSync(file, { throwIfNoEntry: false })?.isFile();
}

function matchesFile(pattern) {
  if (!GLOB.test(pattern)) return isFile(pattern);
  return fs.globSync(pattern).some(isFile);
}

function backtickedPath(token) {
  const candidate = token === "@AGENTS.md" ? "AGENTS.md" : token;
  if (/\s/.test(candidate) || EXTERNAL.test(candidate)) return false;
  if (candidate.startsWith("/")) {
    return fs.existsSync(candidate.split("/")[1]);
  }
  return (
    candidate.includes("/") ||
    /^\.[a-z0-9]+$/i.test(path.extname(candidate)) ||
    GLOB.test(candidate)
  );
}

function linkedDestinations(prose) {
  const destinations = [];
  for (const pattern of [
    /\]\(\s*(?:<([^>\n]+)>|([^\s)]+))/g,
    /^ {0,3}\[[^\]\n]+\]:[ \t]*(?:<([^>\n]+)>|(\S+))/gm,
  ]) {
    for (const [, angle, bare] of prose.matchAll(pattern)) destinations.push(angle ?? bare);
  }
  return destinations.filter((destination) => !EXTERNAL.test(destination));
}

function linkedFailure(guide, destination) {
  const [location, fragment] = destination.split(/#(.*)/s, 2);
  let file;
  let anchor;
  try {
    file = location ? guidePath(guide, decodeURIComponent(location)) : guide;
    anchor = fragment ? decodeURIComponent(fragment) : "";
  } catch {
    return `references invalid Markdown link \`${destination}\``;
  }
  if (!fs.existsSync(file)) return `references missing linked path \`${destination}\``;
  if (!anchor) return null;
  if (isFile(file)) {
    const target = fs.readFileSync(file, "utf8");
    const markdown = /\.md$/i.test(file);
    if (markdownAnchors(target, markdown).has(anchor)) return null;
    if (!markdown && hasLineAnchor(target, anchor)) return null;
  }
  return `references missing anchor \`${destination}\``;
}

function hasLineAnchor(source, anchor) {
  const [start, end = start, extra] = anchor.split("-");
  const line = /^L[1-9]\d*$/;
  if (extra !== undefined || !line.test(start) || !line.test(end)) return false;
  const first = Number(start.slice(1));
  const last = Number(end.slice(1));
  return first <= last && last <= source.replace(/\n$/, "").split("\n").length;
}

function packageScripts(manifest) {
  if (!fs.existsSync(manifest)) return null;
  return new Set(Object.keys(JSON.parse(fs.readFileSync(manifest, "utf8")).scripts ?? {}));
}

function nearestScripts(guide) {
  let dir = path.dirname(guide);
  while (dir !== ".") {
    const scripts = packageScripts(path.join(dir, "package.json"));
    if (scripts) return scripts;
    dir = path.dirname(dir);
  }
  return new Set();
}

function hasWorkspaceScript(workspace, script) {
  // Let pnpm resolve workspace selectors without running any project scripts.
  const output = execFileSync(
    "pnpm",
    [`--filter=${workspace}`, "list", "--depth", "-1", "--json"],
    {
      encoding: "utf8",
    },
  );
  const selected = JSON.parse(output);
  return (
    selected.length > 0 &&
    selected.every(({ path: dir }) => packageScripts(path.join(dir, "package.json"))?.has(script))
  );
}

function scriptFailures(guide, commands) {
  const failures = [];
  const nearest = nearestScripts(guide);
  const root = packageScripts("package.json") ?? new Set();
  const unquote = (word) => word?.replace(/^(['"])(.*)\1$/, "$2");
  for (const command of commands) {
    const words = command.match(/"[^"]*"|'[^']*'|[^\s;&|]+/g) ?? [];
    if (words[0] === "$") words.shift();
    if (words.shift() !== "pnpm") continue;
    const workspace = words[0] === "--filter" ? unquote(words.splice(0, 2)[1]) : null;
    const explicitRun = words[0] === "run";
    if (explicitRun) words.shift();
    const script = unquote(words[0]);
    if (!script || script.startsWith("-") || (!explicitRun && PNPM_BUILT_INS.has(script))) continue;
    if (workspace && !explicitRun) continue;
    const exists = workspace
      ? hasWorkspaceScript(workspace, script)
      : nearest.has(script) || root.has(script);
    if (!exists)
      failures.push(
        `references missing pnpm script \`${script}\`${workspace ? ` in ${workspace}` : ""}`,
      );
  }
  return failures;
}

export function referenceFailures(guide, source) {
  const { prose, fenced } = markdownParts(source);
  const triggers = guideTriggers(prose);
  const failures = [];
  if (!triggers) failures.push("missing ## Guide triggers section");
  else if (triggers.length === 0) failures.push("## Guide triggers must list at least one glob");
  for (const trigger of triggers ?? []) {
    if (!matchesFile(guidePath(guide, trigger)))
      failures.push(`trigger \`${trigger}\` matches no files`);
  }
  const inline = [...prose.matchAll(INLINE_CODE)].map(([, , token]) => token.trim());
  for (const token of new Set(inline)) {
    if (triggers?.includes(token) || !backtickedPath(token)) continue;
    const file = guidePath(guide, token === "@AGENTS.md" ? "AGENTS.md" : token);
    if (!(GLOB.test(file) ? matchesFile(file) : fs.existsSync(file))) {
      failures.push(`references missing path \`${token}\``);
    }
  }
  for (const destination of new Set(linkedDestinations(prose.replace(INLINE_CODE, "")))) {
    const failure = linkedFailure(guide, destination);
    if (failure) failures.push(failure);
  }
  failures.push(...scriptFailures(guide, new Set([...inline, ...fenced])));
  return failures.map((failure) => `${guide}: ${failure}`);
}
