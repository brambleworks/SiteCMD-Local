/**
 * Blanks lines whose first non-space character is `#`, so a YAML comment
 * cannot forge or hide a marker for `orderedBefore`. Line count and the
 * newlines between lines are preserved, so relative ordering of the
 * remaining content is unaffected.
 */
function withoutHashCommentLines(source) {
  return source
    .split("\n")
    .map((line) => (/^[ \t]*#/.test(line) ? "" : line))
    .join("\n");
}

export function orderedBefore(source, first, second) {
  const searchable = withoutHashCommentLines(source);
  const firstIndex = searchable.indexOf(first);
  if (firstIndex === -1) return false;
  const secondIndex = searchable.indexOf(second);
  if (secondIndex === -1) return false;
  return firstIndex < secondIndex;
}

function lineNumberFor(source, index) {
  return source.slice(0, index).split("\n").length;
}

export function tracingInstrumentAttributes(source) {
  const attributes = [];
  let index = 0;
  const marker = "#[tracing::instrument";

  while (index < source.length) {
    const start = source.indexOf(marker, index);
    if (start === -1) break;

    const end = source.indexOf("]", start);
    if (end === -1) break;

    attributes.push({
      text: source.slice(start, end + 1),
      line: lineNumberFor(source, start),
    });
    index = end + 1;
  }

  return attributes;
}

/** Removes JavaScript comments without treating comment markers in strings as comments. */
export function stripJsComments(source) {
  let out = "";
  let quote = null;
  for (let index = 0; index < source.length; index += 1) {
    const char = source[index];
    const next = source[index + 1];
    if (quote) {
      out += char;
      if (char === "\\") {
        out += next ?? "";
        index += 1;
      } else if (char === quote) {
        quote = null;
      }
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      quote = char;
      out += char;
      continue;
    }
    if (char === "/" && next === "/") {
      while (index < source.length && source[index] !== "\n") index += 1;
      out += "\n";
      continue;
    }
    if (char === "/" && next === "*") {
      index += 2;
      while (index < source.length && !(source[index] === "*" && source[index + 1] === "/")) {
        index += 1;
      }
      index += 1;
      out += " ";
      continue;
    }
    out += char;
  }
  return out;
}

/** Reads a balanced object-literal value expression for `key`. */
export function workflowJobEnvironments(workflow) {
  const lines = workflow.split("\n");
  const indent = (line) => line.length - line.trimStart().length;
  const meaningful = (line) => line.trim() !== "" && !line.trimStart().startsWith("#");
  const found = [];
  const start = lines.findIndex((line) => /^jobs:\s*(?:#|$)/.test(line));
  if (start === -1) return found;
  let [job, jobIndent, keyIndent] = [null, null, null];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (!meaningful(line)) continue;
    const depth = indent(line);
    if (depth === 0) break;
    jobIndent ??= depth;
    if (depth === jobIndent) {
      [job, keyIndent] = [line.trim().replace(/:.*$/, ""), null];
      continue;
    }
    keyIndent ??= depth;
    if (depth !== keyIndent || !/^environment\s*:/.test(line.trimStart())) continue;
    let block = line.trim();
    while (i + 1 < lines.length && (!meaningful(lines[i + 1]) || indent(lines[i + 1]) > depth)) {
      i += 1;
      block += `\n${lines[i]}`;
    }
    found.push({ job, block });
  }
  return found;
}

export function workflowBlock(source, key, indent = 0) {
  const prefix = " ".repeat(indent);
  const keys = [key, `"${key}"`, `'${key}'`].map((name) => `${prefix}${name}:`);
  const lines = source.split("\n");
  const start = lines.findIndex((line) => keys.some((name) => line.startsWith(name)));
  if (start === -1) return "";
  const end = lines.findIndex(
    (line, index) =>
      index > start &&
      line.trim() &&
      !line.trimStart().startsWith("#") &&
      !line.startsWith(`${prefix} `) &&
      !line.startsWith(`${prefix}- `),
  );
  return lines.slice(start, end === -1 ? undefined : end).join("\n");
}

export function unconditionalWorkflowStep(step) {
  return !/^ {8}(?:if|continue-on-error):/m.test(`        ${step}`);
}

export function workflowStepIndex(source, runLine) {
  return source
    .split(/^ {6}- /m)
    .slice(1)
    .findIndex(
      (step) =>
        unconditionalWorkflowStep(step) &&
        `        ${step}`.split("\n").includes(`        ${runLine}`),
    );
}
