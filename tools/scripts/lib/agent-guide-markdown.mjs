export function markdownParts(source) {
  const prose = [];
  const fenced = [];
  let fence;
  for (const line of source.split(/\r?\n/)) {
    const marker = /^ {0,3}(`{3,}|~{3,})(.*)$/.exec(line);
    if (fence) {
      if (marker && marker[1].startsWith(fence) && marker[2].trim() === "") fence = undefined;
      else fenced.push(line);
      prose.push("");
    } else if (marker) {
      fence = marker[1];
      prose.push("");
    } else {
      prose.push(line);
    }
  }
  return { prose: prose.join("\n"), fenced };
}

export function guideTriggers(prose) {
  const heading = /^ {0,3}##[ \t]+Guide triggers[ \t]*$/m.exec(prose);
  if (!heading) return null;
  const body = prose.slice(heading.index + heading[0].length).split(/^ {0,3}#{1,2}[ \t]/m)[0];
  return [...body.matchAll(/^ {0,3}[-*+][ \t]+(.+)$/gm)].map(([, entry]) =>
    entry.trim().replace(/^`(.+)`$/, "$1"),
  );
}

// Repeats until nothing changes, so removing one tag cannot leave another behind.
function withoutTags(text) {
  let previous;
  do {
    previous = text;
    text = text.replace(/<[^>]+>/g, "");
  } while (text !== previous);
  return text;
}

export function markdownAnchors(source, markdown) {
  const anchors = new Set();
  const prose = markdown ? markdownParts(source).prose : source;
  for (const match of prose.matchAll(/<[a-z][^<>]*\s(?:id|name)=["']([^"']+)["']/gi)) {
    anchors.add(match[1]);
  }
  if (!markdown) return anchors;

  const used = new Set();
  const lines = prose.split("\n");
  for (const [index, line] of lines.entries()) {
    const atx = /^ {0,3}#{1,6}[ \t]+(.+)$/.exec(line);
    const setext = /^ {0,3}(?:=+|-+)[ \t]*$/.test(lines[index + 1] ?? "");
    if (!atx && (!setext || !line.trim())) continue;
    const slug = withoutTags(
      (atx?.[1] ?? line).replace(/[ \t]+#+[ \t]*$/, "").replace(/\[([^\]]+)\]\([^)]*\)/g, "$1"),
    )
      .replace(/(?:\*\*|__)(.+?)(?:\*\*|__)/g, "$1")
      .trim()
      .toLowerCase()
      .replace(/[^\p{L}\p{M}\p{N}\p{Zs}_-]/gu, "")
      .replace(/\p{Zs}/gu, "-");
    let anchor = slug;
    for (let suffix = 1; used.has(anchor); suffix += 1) anchor = `${slug}-${suffix}`;
    used.add(anchor);
    anchors.add(anchor);
  }
  return anchors;
}
