const TOML_TOKEN =
  /#[^\r\n]*|"""(?:\\[\s\S]|"(?!"")|[^"\\])*"{3,5}|'''(?:'(?!'')|[^'])*'{3,5}|"(?:\\.|[^"\\])*"|'[^']*'|[\w-]+|[^\s]|\n/g;

const BASIC_ESCAPES = { b: "\b", t: "\t", n: "\n", f: "\f", r: "\r", e: "\u001b" };

/** @public Every token in order; tooling outside the public tree reads it. */
export function tomlTokens(source) {
  return source.matchAll(TOML_TOKEN);
}

export function tomlText(token = "") {
  const quote = token[0];
  if (quote !== "'" && quote !== '"') return token;
  const multiline = token.startsWith(quote.repeat(3));
  const delimiterLength = multiline ? 3 : 1;
  const contents = token.slice(delimiterLength, -delimiterLength);
  const text = multiline ? contents.replace(/^\r?\n/, "") : contents;
  if (quote === "'") return text;
  return text.replace(
    /\\(?:([ \t]*\r?\n[ \t\r\n]*)|x([\da-fA-F]{2})|u([\da-fA-F]{4})|U([\da-fA-F]{8})|([^\r\n]))/g,
    (escape, continuation, byte, short, long, character) => {
      if (continuation !== undefined) return multiline ? "" : escape;
      const hex = byte ?? short ?? long;
      if (hex !== undefined) {
        const codePoint = parseInt(hex, 16);
        return codePoint <= 0x10ffff ? String.fromCodePoint(codePoint) : escape;
      }
      return BASIC_ESCAPES[character] ?? character;
    },
  );
}

export function tomlFields(source) {
  // Flatten fields so dotted keys, dependency tables and inline declarations match alike.
  const tokens = (source.match(TOML_TOKEN) ?? []).filter((token) => !token.startsWith("#"));
  const fields = [];
  let index = 0;
  let table = [];
  function keys() {
    const path = [tomlText(tokens[index++])];
    while (tokens[index] === ".") {
      index++;
      path.push(tomlText(tokens[index++]));
    }
    return path;
  }
  function assignment(prefix) {
    const path = [...prefix, ...keys()];
    if (tokens[index++] !== "=") return;
    const value = tokens[index++];
    if (value === "{") {
      while (index < tokens.length && tokens[index] !== "}") {
        if ([",", "\n"].includes(tokens[index])) index++;
        else assignment(path);
      }
      index++;
    } else if (value === "[") {
      let depth = 1;
      const start = index;
      while (index < tokens.length && depth > 0) {
        if (tokens[index] === "[") depth++;
        if (tokens[index] === "]") depth--;
        index++;
      }
      fields.push({
        path,
        value: tokens.slice(start, index - 1).filter((token) => token !== "\n"),
      });
    } else if (value !== undefined) {
      fields.push({ path, value: tomlText(value) });
    }
  }
  while (index < tokens.length) {
    if (tokens[index] === "\n") {
      index++;
      continue;
    }
    if (tokens[index] === "[") {
      index++;
      if (tokens[index] === "[") index++;
      table = keys();
    } else {
      assignment(table);
    }
    while (index < tokens.length && tokens[index] !== "\n") index++;
  }
  return fields;
}
