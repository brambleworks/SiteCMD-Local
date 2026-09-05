const PAGE_ALIASES = new Map([
  ["dashboard", "dashboard"],
  ["today", "today"],
  ["search", "search-console"],
  ["seo", "search-console"],
  ["security", "security"],
  ["updates", "updates"],
  ["analytics", "analytics"],
  ["integrations", "integrations"],
  ["events", "events"],
  ["deploys", "deploys"],
  ["scans", "scans"],
  ["scan", "scans"],
  ["settings", "settings"],
]);

const OPTIONS = new Map([
  ["--project", "projectId"],
  ["--url", "url"],
  ["--focus", "focus"],
  ["--item", "itemId"],
  ["--lane", "lane"],
]);

/** Desktop navigation is explicit so it cannot shadow a scanner subcommand. */
export function desktopInvocation(args, platform) {
  const page = PAGE_ALIASES.get(args[0]);
  if (!page) throw new Error("Usage: pnpm sitecmd -- open <page> [--project <id>] [--url <url>]");
  const url = new URL("sitecmd://open");
  url.searchParams.set("page", page);
  for (let index = 1; index < args.length; index += 2) {
    const key = OPTIONS.get(args[index]);
    const value = args[index + 1];
    if (!key) throw new Error(`Unknown desktop option: ${args[index]}`);
    if (!value || value.startsWith("--")) throw new Error(`Missing value for ${args[index]}`);
    if ((key === "projectId" || key === "itemId") && !/^[1-9]\d*$/.test(value)) {
      throw new Error(`${args[index]} must be a positive integer`);
    }
    url.searchParams.set(key, value);
  }
  if (platform === "darwin") return { command: "open", args: [url.toString()] };
  if (platform === "win32") {
    // PowerShell receives the URI as data through a single-quoted literal.
    const literal = url.toString().replaceAll("'", "''");
    return {
      command: "powershell.exe",
      args: ["-NoProfile", "-NonInteractive", "-Command", `Start-Process '${literal}'`],
    };
  }
  return { command: "xdg-open", args: [url.toString()] };
}
