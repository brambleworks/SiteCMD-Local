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

export function lineNumberFor(source, index) {
  return source.slice(0, index).split("\n").length;
}

function isIdentifierChar(value) {
  return /[A-Za-z0-9_$]/.test(value);
}

function skipWhitespace(source, index) {
  while (index < source.length && /\s/.test(source[index])) index += 1;
  return index;
}

function skipGenericArgument(source, index) {
  if (source[index] !== "<") return index;

  let quote = null;
  let depth = 0;
  for (let cursor = index; cursor < source.length; cursor += 1) {
    const ch = source[cursor];
    if (quote) {
      if (ch === quote && source[cursor - 1] !== "\\") quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "<") {
      depth += 1;
    } else if (ch === ">") {
      depth -= 1;
      if (depth === 0) return cursor + 1;
    } else if (ch === "\n" && depth <= 0) {
      return index;
    }
  }

  return index;
}

function readFirstCallArgument(source, index) {
  let quote = null;
  for (let cursor = index; cursor < source.length; cursor += 1) {
    const ch = source[cursor];
    if (quote) {
      if (ch === quote && source[cursor - 1] !== "\\") quote = null;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }
    if (ch === "," || ch === ")" || ch === "\n") {
      return source.slice(index, cursor).trim();
    }
  }
  return source.slice(index).trim();
}

export function findInvokeCalls(source) {
  const calls = [];
  let cursor = 0;

  while (cursor < source.length) {
    const invokeIndex = source.indexOf("invoke", cursor);
    if (invokeIndex === -1) break;

    const before = source[invokeIndex - 1] ?? "";
    const after = source[invokeIndex + "invoke".length] ?? "";
    if (isIdentifierChar(before) || isIdentifierChar(after)) {
      cursor = invokeIndex + "invoke".length;
      continue;
    }

    let callIndex = skipWhitespace(source, invokeIndex + "invoke".length);
    callIndex = skipWhitespace(source, skipGenericArgument(source, callIndex));
    if (source[callIndex] !== "(") {
      cursor = invokeIndex + "invoke".length;
      continue;
    }

    const firstArgStart = skipWhitespace(source, callIndex + 1);
    calls.push({
      arg: readFirstCallArgument(source, firstArgStart),
      index: invokeIndex,
    });
    cursor = callIndex + 1;
  }

  return calls;
}

// Returns tracing attributes with their 1-based line numbers.
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
export function objectValueExpression(source, key) {
  const at = source.indexOf(`"${key}"`);
  if (at < 0) return "";
  let index = source.indexOf(":", at + key.length + 2);
  if (index < 0) return "";
  index += 1;
  let depth = 0;
  let value = "";
  for (; index < source.length; index += 1) {
    const char = source[index];
    if ("([{".includes(char)) depth += 1;
    else if (")]}".includes(char)) {
      if (depth === 0) break;
      depth -= 1;
    } else if (char === "," && depth === 0) break;
    value += char;
  }
  return value.trim();
}

/**
 * Each GitHub Actions job's `environment:` line with every deeper line under
 * it, read by indentation, so the url-first, flow and expression forms are all
 * visible without a YAML parser.
 */
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
