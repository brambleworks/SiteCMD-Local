const MAIN = "apps/desktop/src-tauri/crates/cli/src/main.rs";
const CLI = "apps/desktop/src-tauri/crates/cli/src";
const RUNTIME = "apps/desktop/src-tauri/src/cli";

function parserFlags(read, exists, command) {
  const main = read(MAIN);
  const parser =
    new RegExp(`fn parse_${command}_args\\([\\s\\S]*?(?=\\nfn |$)`).exec(main)?.[0] ?? "";
  const sources = [parser];
  for (const file of [
    `${CLI}/${command}_dispatch.rs`,
    `${RUNTIME}/${command}.rs`,
    `${RUNTIME}/${command}/mod.rs`,
  ]) {
    if (exists(file)) sources.push(read(file));
  }
  return new Set(
    [...sources.join("\n").matchAll(/"(--?[a-zA-Z][a-zA-Z-]*)"/g)].map((match) => match[1]),
  );
}

/** Validate local command usage without maintaining a second CLI reference. */
export function cliDocumentationFailures(read, exists, commands) {
  const failures = [];
  const source = read("README.md");
  const invocations = [
    ...[...source.matchAll(/`sitecmd ([^`\n]+)`/g)].map((match) => match[1]),
    ...[
      ...source.matchAll(/^(?:sitecmd |pnpm sitecmd -- |npx (?:@sitecmd\/cli|sitecmd) )([^\n]+)/gm),
    ].map((match) => match[1]),
  ];
  const documented = new Set();
  const documentedFlags = new Map();
  for (const invocation of invocations) {
    const [command, ...args] = invocation.trim().split(/\s+/);
    if (command.startsWith("<") || command.startsWith("-")) continue;
    documented.add(command);
    if (!commands.has(command)) {
      failures.push(`sitecmd ${command} is documented but not dispatched by ${MAIN}.`);
      continue;
    }
    const accepted = parserFlags(read, exists, command);
    const flags = documentedFlags.get(command) ?? new Set();
    for (const flag of args.filter((arg) => /^--?[a-zA-Z]/.test(arg))) {
      flags.add(flag);
      if (!accepted.has(flag)) {
        failures.push(`sitecmd ${command} documents unsupported option ${flag} in README.md.`);
      }
    }
    documentedFlags.set(command, flags);
  }
  for (const command of commands) {
    if (!documented.has(command)) {
      failures.push(`sitecmd ${command} has no CLI reference entry in README.md.`);
    }
  }
  for (const flag of parserFlags(read, exists, "rules")) {
    if (!documentedFlags.get("rules")?.has(flag)) {
      failures.push(`sitecmd rules option ${flag} has no README documentation.`);
    }
  }
  return failures;
}
