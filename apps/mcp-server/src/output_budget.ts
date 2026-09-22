/** Keep entries whole across pages unless the first entry alone exceeds the budget. */
export function formatBoundedEntries<T>(
  values: T[],
  format: (value: T) => string,
  maxChars: number,
) {
  const entries: string[] = [];
  let length = 0;
  let shortened = false;
  for (const value of values) {
    const entry = format(value);
    const separatorLength = entries.length > 0 ? 2 : 0;
    if (length + separatorLength + entry.length > maxChars) {
      if (entries.length === 0) {
        let end = maxChars - 4;
        const last = entry.charCodeAt(end - 1);
        if (last >= 0xd800 && last <= 0xdbff) end -= 1;
        entries.push(`${entry.slice(0, end)}\n...`);
      }
      shortened = true;
      break;
    }
    entries.push(entry);
    length += separatorLength + entry.length;
  }
  return { body: entries.join("\n\n"), count: entries.length, shortened };
}
