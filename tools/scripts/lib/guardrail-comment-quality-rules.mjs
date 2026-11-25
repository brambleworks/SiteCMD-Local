const ALLOW_MARKER = "allow-comment-phrase";

const BANNED = [
  [/\bbasically\b/i, "basically"],
  [/\bsimply\b/i, "simply"],
  [/\bessentially\b/i, "essentially"],
  [/\bnote that\b/i, "note that"],
  [/\bin order to\b/i, "in order to"],
  [/\bof course\b/i, "of course"],
  [/\bunder the hood\b/i, "under the hood"],
  [/\bworth noting\b/i, "worth noting"],
  [/\bas (?:we|you) can see\b/i, "as we can see"],
  [/\bneedless to say\b/i, "needless to say"],
  [/\bhere we\b/i, "here we"],
  [/\bnow we\b/i, "now we"],
];

// Private tool names are banned only when used as design authorities.
const PRIVATE_TOOLING = [
  [/\bstitch[-\s](?:styled|style|design|theme)\b/i, "Stitch"],
  [/\bstitch\s+"/i, "Stitch"],
  [/\bimpeccable\s+(?:skill|hook|design\.json)\b/i, "Impeccable"],
  [/\bsuperpowers\s+(?:skill|plugin)\b/i, "Superpowers"],
];

const TARGETS = [
  ["apps/desktop/src-tauri/src", (f) => f.endsWith(".rs")],
  ["apps/desktop/src-tauri/crates", (f) => f.endsWith(".rs")],
];

function langFor(file) {
  if (file.endsWith(".css")) return "css";
  if (file.endsWith(".rs")) return "rust";
  return "ts";
}

// Skip a quoted string while preserving line accounting.
function skipString(source, start, delim, onNewline) {
  const n = source.length;
  let i = start + 1;
  while (i < n) {
    const ch = source[i];
    if (ch === "\\") {
      i += 2;
      continue;
    }
    if (ch === "\n") onNewline();
    if (ch === delim) return i + 1;
    i += 1;
  }
  return n;
}

// Distinguish Rust character literals from lifetimes.
function skipRustQuote(source, start) {
  const n = source.length;
  if (source[start + 1] === "\\") {
    let i = start + 2;
    while (i < n && source[i] !== "'" && source[i] !== "\n") i += 1;
    return source[i] === "'" ? i + 1 : start + 1;
  }
  if (source[start + 2] === "'") return start + 3;
  return start + 1;
}

// Extract line-mapped comments without matching comment syntax inside literals.
function extractComments(source, lang) {
  const comments = [];
  const n = source.length;
  const isRust = lang === "rust";
  let i = 0;
  let line = 1;
  const bumpLine = () => {
    line += 1;
  };
  while (i < n) {
    const ch = source[i];
    const next = source[i + 1];
    if (ch === "\n") {
      line += 1;
      i += 1;
      continue;
    }
    if (ch === "/" && next === "/" && lang !== "css") {
      let text = "";
      i += 2;
      while (i < n && source[i] !== "\n") {
        text += source[i];
        i += 1;
      }
      comments.push({ startLine: line, text });
      continue;
    }
    if (ch === "/" && next === "*") {
      const startLine = line;
      let text = "";
      i += 2;
      while (i < n && !(source[i] === "*" && source[i + 1] === "/")) {
        if (source[i] === "\n") line += 1;
        text += source[i];
        i += 1;
      }
      i += 2;
      comments.push({ startLine, text });
      continue;
    }
    if (isRust && ch === "r") {
      let k = i + 1;
      let hashes = 0;
      while (source[k] === "#") {
        hashes += 1;
        k += 1;
      }
      if (source[k] === '"') {
        const close = `"${"#".repeat(hashes)}`;
        const end = source.indexOf(close, k + 1);
        const stop = end === -1 ? n : end + close.length;
        for (let p = i; p < stop; p += 1) if (source[p] === "\n") line += 1;
        i = stop;
        continue;
      }
    }
    if (ch === '"' || (ch === "`" && !isRust)) {
      i = skipString(source, i, ch, bumpLine);
      continue;
    }
    if (ch === "'") {
      i = isRust ? skipRustQuote(source, i) : skipString(source, i, "'", bumpLine);
      continue;
    }
    i += 1;
  }
  return comments;
}

export function commentQualityFailures(read, listFiles) {
  const failures = [];
  for (const [dir, predicate] of TARGETS) {
    for (const file of listFiles(dir, predicate)) {
      const source = read(file);
      if (!source.includes("//") && !source.includes("/*")) continue;
      const sourceLines = source.split("\n");
      const lang = langFor(file);
      for (const comment of extractComments(source, lang)) {
        const segments = comment.text.split("\n");
        for (let k = 0; k < segments.length; k += 1) {
          const physicalLine = comment.startLine + k;
          const raw = sourceLines[physicalLine - 1] ?? "";
          if (raw.includes(ALLOW_MARKER)) continue;
          for (const [pattern, label] of BANNED) {
            if (pattern.test(segments[k])) {
              failures.push(
                `${file}:${physicalLine} - comment uses filler "${label}"; state it plainly or drop it (add ${ALLOW_MARKER} when the word is the subject). Line: ${raw.trim()}`,
              );
            }
          }
          for (const [pattern, label] of PRIVATE_TOOLING) {
            if (pattern.test(segments[k])) {
              failures.push(
                `${file}:${physicalLine} - comment cites ${label}, a maintainer-only tool absent from this repository; point at the in-repo reference instead (the codebase, src/styles/COMPONENT_GUIDE.md). Line: ${raw.trim()}`,
              );
            }
          }
        }
      }
    }
  }
  return failures;
}
