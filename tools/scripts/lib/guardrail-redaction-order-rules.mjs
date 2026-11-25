import { walkProdLines } from "./guardrail-rust-rules.mjs";
import { stripNonCode } from "./guardrail-source-text.mjs";

const REDACTION = /\bredact_[a-z_]+\s*\(/g;
const CUT =
  /\b(?:truncate\w*|\w*window\w*|\w*slice\w*|floor_char_boundary)\s*\(|\.(?:chars|bytes|lines|split_inclusive)\s*\([^)]*\)\s*\.(?:take|skip|nth|next)\s*\(|\.(?:get|get_unchecked)\s*\([^)]*\.\.|\.split_at\s*\(|\[[^\]\n]*\.\.[^\]\n]*\]/;

const LOG_EVIDENCE_HELPER =
  /\b(?:bounded_(?:issue_evidence|log_diagnostic|evidence)|evidence_safe_(?:page_url(?:_for_site)?|url_reference)|log_safe_(?:page_url(?:_for_site)?|url_reference)|redact_(?:issue_evidence|log_diagnostic|(?:log_)?config_credentials|secrets_with_url_mask|url_credentials)|prepare_(?:config_credentials|issue_evidence)|sanitize_(?:page_url(?:_for_site)?|url_reference))\b|\*/;
const PRIVATE_LOG_DEPENDENCY =
  /\b(?:checks|evaluation|evidence_redaction|key_patterns|literal_coverage_tests|redact_key_patterns)\b/;

function usesLogEvidenceHelper(source, allowRedactSecrets) {
  const aliases = [];
  for (const match of source.matchAll(/\blog_sanitizer\s*(?:as\s+(\w+)|::\s*(?=\{))/g)) {
    if (match[1]) aliases.push(match[1]);
    else {
      const start = match.index + match[0].length;
      const group = source.slice(start, afterBalanced(source, start));
      for (const alias of group.matchAll(/\bself\s+as\s+(\w+)/g)) aliases.push(alias[1]);
    }
  }
  const modules = ["log_sanitizer", ...aliases].join("|");
  const members = new RegExp(`\\b(?:${modules})\\s*::\\s*(\\w+|\\*|\\{)`, "g");
  for (const match of source.matchAll(members)) {
    const start = match.index + match[0].length - match[1].length;
    const member = match[1] === "{" ? source.slice(start, afterBalanced(source, start)) : match[1];
    if (
      LOG_EVIDENCE_HELPER.test(member) ||
      (!allowRedactSecrets && /\bredact_secrets\b/.test(member))
    )
      return true;
  }
  return false;
}

function usesSourceInclude(source) {
  if (/\binclude\s*!/.test(source)) return true;
  for (const attribute of source.matchAll(/#\s*!?\s*\[/g)) {
    const start = attribute.index + attribute[0].length - 1;
    if (/\bpath\s*=/.test(source.slice(start, afterBalanced(source, start)))) return true;
  }
  return false;
}

const references = (names, expression) =>
  [...names].some((name) => new RegExp(`\\b${name}\\b`).test(expression));
const callsHelper = (helpers, expression) =>
  [...helpers].some((name) => new RegExp(`\\b${name}\\s*\\(`).test(expression));

function bindings(source, helpers) {
  const cuts = new Set();
  const iterators = new Set();
  const lineIterators = new Set();
  for (const statement of source.matchAll(
    /\blet\s+(?:mut\s+|)(?<name>\w+)(?:\s*:[^=;]+|)\s*=\s*(?<expression>[\s\S]*?);|\b(?<mutated>\w+)\.truncate\s*\([^;]*;/g,
  )) {
    const { name, expression, mutated } = statement.groups;
    if (mutated) {
      cuts.add(mutated);
      continue;
    }
    if (isCut(expression, cuts, new Set([...iterators, ...lineIterators]), helpers)) cuts.add(name);
    else cuts.delete(name);
    if (/\.(?:chars|bytes)\s*\(/.test(expression) || references(iterators, expression))
      iterators.add(name);
    else iterators.delete(name);
    if (
      (/\.(?:lines|split_inclusive)\s*\(/.test(expression) ||
        references(lineIterators, expression)) &&
      !/\.(?:collect|next|nth)\s*(?:\(|::)/.test(expression)
    )
      lineIterators.add(name);
    else lineIterators.delete(name);
  }
  return { cuts, iterators: new Set([...iterators, ...lineIterators]) };
}

function afterBalanced(source, start) {
  const closing = { "(": ")", "[": "]", "{": "}" };
  const stack = [closing[source[start]]];
  let end = start + 1;
  while (end < source.length && stack.length) {
    if (closing[source[end]]) stack.push(closing[source[end]]);
    else if (source[end] === stack.at(-1)) stack.pop();
    end++;
  }
  return end;
}

function summarySource(body) {
  const safe = [...body.matchAll(/\blet\s+(\w+)\s*=\s*(?:[\w:]+::|)redact_\w+\s*\(/g)].map(
    (match) => match[1],
  );
  for (const name of safe) {
    const pattern = new RegExp(`\\b${name}\\b`, "g");
    const matches = [...body.matchAll(pattern)].reverse();
    for (const match of matches) {
      let end = match.index + name.length;
      while (true) {
        const tail = body.slice(end);
        const method = tail.match(/^\s*\.\s*\w+\s*(?=\()/);
        const bracket = tail.match(/^\s*(?=\[)/);
        if (method) end = afterBalanced(body, end + method[0].length);
        else if (bracket) end = afterBalanced(body, end + bracket[0].length);
        else break;
      }
      body = body.slice(0, match.index) + "safe_value" + body.slice(end);
    }
  }
  return body;
}

function isCut(expression, cuts, iterators, helpers) {
  return (
    CUT.test(expression) ||
    references(cuts, expression) ||
    callsHelper(helpers, expression) ||
    (/\.(?:take|skip|nth|next)\s*\(/.test(expression) && references(iterators, expression))
  );
}

function cutHelpers(source) {
  const functions = [];
  for (const match of source.matchAll(/\bfn\s+(\w+)[^{;]*\{/g)) {
    let depth = 1;
    let end = match.index + match[0].length;
    const start = end;
    while (end < source.length && depth) {
      if (source[end] === "{") depth++;
      if (source[end] === "}") depth--;
      end++;
    }
    functions.push({ name: match[1], body: summarySource(source.slice(start, end - 1)) });
  }
  const helpers = new Set();
  let changed = true;
  while (changed) {
    changed = false;
    for (const { name, body } of functions) {
      if (helpers.has(name)) continue;
      const { cuts, iterators } = bindings(body, helpers);
      const returned = [
        body.slice(body.lastIndexOf(";") + 1),
        ...[...body.matchAll(/\breturn\s+([^;]+);/g)].map((match) => match[1]),
      ];
      if (returned.some((expression) => isCut(expression, cuts, iterators, helpers))) {
        helpers.add(name);
        changed = true;
      }
    }
  }
  return helpers;
}

function callArgument(source, start) {
  let depth = 1;
  for (let i = start; i < source.length; i++) {
    if (source[i] === "(") depth++;
    if (source[i] === ")" && --depth === 0) return source.slice(start, i);
  }
  return source.slice(start);
}

export function redactionOrderFailures(
  read,
  listFiles,
  { evidenceProducer = () => false, comparisonTest } = {},
) {
  const failures = [];
  const isLogSanitizer = (name) => /\/log_sanitizer(?:\.rs$|\/)/.test(name);
  const isTest = (name) => /(?:\/tests\/|_tests?\.rs$|\/tests\.rs$)/.test(name);
  for (const dir of ["apps/desktop/src-tauri/src", "apps/desktop/src-tauri/crates"]) {
    for (const file of listFiles(
      dir,
      (name) =>
        name.endsWith(".rs") && (isLogSanitizer(name) || evidenceProducer(name) || !isTest(name)),
    )) {
      const raw = read(file);
      const code = stripNonCode(raw, file);
      if (isLogSanitizer(file) && (PRIVATE_LOG_DEPENDENCY.test(code) || usesSourceInclude(code))) {
        failures.push(`${file} - keep the detector key table out of the log sanitizer.`);
      }
      if (evidenceProducer(file) && usesLogEvidenceHelper(code, file === comparisonTest)) {
        failures.push(`${file} - use evidence_redaction for scan evidence.`);
      }
      if (isTest(file)) continue;
      if (
        file.endsWith("/supply_chain/github_actions.rs") &&
        !/fn workflow_expression_evidence\(line: &str\)[\s\S]*?let safe_line = redact_evidence\(line\);[\s\S]*?find_iter\(&safe_line\)[\s\S]*?safe_line\[matched\.start\(\)\.\.\]/.test(
          raw,
        )
      ) {
        failures.push(
          `${file} - redact the complete workflow line before extracting expression evidence.`,
        );
      }
      if (
        file.endsWith("/protocol/src/log_sanitizer.rs") &&
        !/let redacted = redact_diagnostic\(trimmed\);\s*let without_query = redacted\.split/.test(
          raw,
        )
      ) {
        failures.push(
          `${file} - redact the complete fallback URL reference before dropping its query suffix.`,
        );
      }
      const lines = [];
      walkProdLines(code, (line, index) => {
        lines[index] = line;
      });
      const source = lines.map((line) => line ?? "").join("\n");
      const helpers = cutHelpers(source);
      for (const call of source.matchAll(REDACTION)) {
        if (/\bfn\s*$/.test(source.slice(Math.max(0, call.index - 4), call.index))) continue;
        const before = source.slice(0, call.index);
        const functionStart = [...before.matchAll(/\bfn\s+\w+/g)].at(-1)?.index ?? 0;
        const { cuts, iterators } = bindings(before.slice(functionStart), helpers);
        const argument = callArgument(source, call.index + call[0].length);
        if (isCut(argument, cuts, iterators, helpers)) {
          const line = source.slice(0, call.index).split("\n").length;
          failures.push(
            `${file}:${line} - redact the complete value before truncating, slicing, or windowing it.`,
          );
        }
      }
    }
  }
  return failures;
}
