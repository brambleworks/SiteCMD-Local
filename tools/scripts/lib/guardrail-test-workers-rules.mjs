import { posix } from "node:path";

import { stripComments, stripNonCode } from "./guardrail-source-text.mjs";

const CONFIG = "vitest.config.mjs";
const WORKER_HELPER = "tools/scripts/lib/test-workers.mjs";
const STATIC_KEY = /^\s*\*?\s*([\w$]+|"[^"\\]*"|'[^'\\]*')\s*(?=[:(]|$)/;

function staticKey(entry) {
  const modifier = /^\s*(?:get|set|async)\s+/.exec(entry)?.[0].length ?? 0;
  const key = STATIC_KEY.exec(entry.slice(modifier)) ?? STATIC_KEY.exec(entry);
  if (!key) return undefined;
  const offset = key.input === entry ? 0 : modifier;
  return { name: key[1].replace(/^["']|["']$/g, ""), end: offset + key[0].length };
}

function importsWorkerCount(source, code) {
  for (const start of source.matchAll(/\bimport\s*/g)) {
    if (!code.startsWith("import", start.index)) continue;
    const clause = source.slice(start.index + start[0].length);
    const named = clause.replace(/^[\w$]+\s*,\s*/, "");
    const match = /^\{([^{}]*)\}\s*from\s*(["'])([^"'\r\n]+)\2/.exec(named);
    if (!match) continue;
    const [, bindings, , specifier] = match;
    const relative = specifier.startsWith("./") || specifier.startsWith("../");
    if (
      relative &&
      posix.normalize(specifier) === WORKER_HELPER &&
      bindings.split(",").some((binding) => binding.trim() === "workerCount")
    ) {
      return true;
    }
  }
  return false;
}

function lastProperty(source, code, name, trailing = /^\s*$/) {
  const open = /^\s*\{/.exec(source);
  if (!open) return undefined;

  let start = open[0].length;
  let depth = 0;
  let value;
  for (let i = start; i < code.length; i += 1) {
    const token = code[i];
    if (depth === 0 && (token === "," || token === "}")) {
      const entry = source.slice(start, i);
      const key = staticKey(entry);
      if (key?.name === name) {
        const colon = start + key.end;
        value =
          code[colon] === ":"
            ? { source: source.slice(colon + 1, i), code: code.slice(colon + 1, i) }
            : undefined;
      } else if (!key && entry.trim()) {
        // A spread or computed key could override the property.
        value = undefined;
      }
      if (token === "}") return trailing.test(source.slice(i + 1)) ? value : undefined;
      start = i + 1;
    } else if ("([{".includes(token)) {
      depth += 1;
    } else if (")]}".includes(token)) {
      depth -= 1;
    }
  }
}

function usesWorkerCount(source, code) {
  const exported = /\bexport\s+default\s+/.exec(code);
  if (!exported) return false;
  const valueStart = exported.index + exported[0].length;
  const wrapper = /^defineConfig\s*\(\s*/.exec(code.slice(valueStart));
  const start = valueStart + (wrapper?.[0].length ?? 0);
  const trailing = wrapper ? /^\s*,?\s*\)\s*(?:;|$)/ : /^\s*(?:;|$)/;
  const test = lastProperty(source.slice(start), code.slice(start), "test", trailing);
  const workers = test && lastProperty(test.source, test.code, "maxWorkers");
  return workers && /^\s*workerCount\s*\(\s*\)\s*$/.test(workers.source);
}

export function testWorkerFailures(read) {
  const text = read(CONFIG);
  const source = stripComments(text, CONFIG);
  const code = stripNonCode(text, CONFIG);
  if (importsWorkerCount(source, code) && usesWorkerCount(source, code)) return [];
  return [`${CONFIG}: set maxWorkers from workerCount() in ${WORKER_HELPER}.`];
}
