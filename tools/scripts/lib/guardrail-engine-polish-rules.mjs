// A hosted polish runner grades what the CLI's polish phase grades: each one
// calls the signal table entry its id names, a page-only one, and both CLI
// phases run that whole table through the engine's run_all_signals and
// polish_check_result, with no runtime copy shadowing either.

import { polishSignals } from "./guardrail-engine-lane-parsing.mjs";

export const RUNNERS_POLISH =
  "apps/desktop/src-tauri/crates/engine/src/evaluation/runners_polish.rs";
const POLISH_TABLE = "apps/desktop/src-tauri/crates/engine/src/checks/polish/mod.rs";
const RUNTIME_POLISH = "apps/desktop/src-tauri/src/checks/polish";
const POLISH_PHASES = [
  "apps/desktop/src-tauri/src/core/scanner.rs",
  "apps/desktop/src-tauri/src/core/scanner/verify.rs",
];

const RUNNER_ROW =
  /covers: &\["polish\.([^"]+)"\],\s*run: \|inputs\| signal_rows\(inputs, ([\w:]+)\),/g;
const RUNS_THE_TABLE = /POLISH_SIGNALS\s*\.iter\(\)\s*\.map\(\|signal\| \(signal\.run\)\(ctx\)\)/;
// A local item of one of these names shadows the runtime's glob re-export.
const SHADOW =
  /\bfn\s+(?:run_all_signals|run_page_signals|polish_check_result|css_signal_counts|extract_stylesheet_urls|stylesheet_request|grade_stylesheet_signals|grade_stylesheet_coverage)\b|\b(?:const|static)\s+(?:POLISH_SIGNALS|STYLESHEET_SAMPLE_LIMIT)\b/;

/** Mask Rust comments and literals while preserving line breaks and token boundaries. */
function code(source) {
  const literal =
    /"(?:\\[\s\S]|[^"\\])*"|'(?:\\(?:u\{[\da-fA-F_]+\}|x[\da-fA-F]{2}|.)|[^'\\\r\n])'/y;
  const output = [];
  let blockDepth = 0;
  let lineComment = false;
  for (let index = 0; index < source.length;) {
    const pair = source.slice(index, index + 2);
    if (lineComment) {
      if (source[index] === "\n") lineComment = false;
    } else if (blockDepth > 0) {
      if (pair === "/*" || pair === "*/") {
        blockDepth += pair === "/*" ? 1 : -1;
        output.push("  ");
        index += 2;
        continue;
      }
    } else if (pair === "//") {
      lineComment = true;
    } else if (pair === "/*") {
      blockDepth = 1;
      output.push("  ");
      index += 2;
      continue;
    } else {
      const raw = source[index] === "r" ? /^r(#*)"/.exec(source.slice(index)) : null;
      literal.lastIndex = index;
      const quoted = raw === null ? literal.exec(source) : null;
      if (raw !== null || quoted !== null) {
        const closing = raw === null ? null : `"${raw[1]}`;
        const end = raw === null ? -1 : source.indexOf(closing, index + raw[0].length);
        const length =
          quoted !== null
            ? quoted[0].length
            : end === -1
              ? source.length - index
              : end + closing.length - index;
        output.push(source.slice(index, index + length).replace(/[^\n]/g, " "));
        index += length;
        continue;
      }
      output.push(source[index++]);
      continue;
    }
    output.push(source[index] === "\n" ? "\n" : " ");
    index += 1;
  }
  return output.join("");
}

/** Dispatch parity between the hosted polish runners and the CLI's polish phase. */
export function polishDispatchFailures(read, listFiles) {
  const source = read(RUNNERS_POLISH);
  const start = source.indexOf("pub const POLISH_RUNNERS");
  const table = read(POLISH_TABLE);
  const signals = polishSignals(table);
  if (start === -1 || signals === null) {
    return [
      `${RUNNERS_POLISH} or ${POLISH_TABLE} no longer declares \`POLISH_RUNNERS\` or \`POLISH_SIGNALS\`; update these rules with them`,
    ];
  }
  const failures = [];
  const end = source.indexOf("\n];", start);
  const block = source.slice(start, end === -1 ? source.length : end);
  const rows = [...block.matchAll(RUNNER_ROW)];
  const invocations = [...block.matchAll(/\brun:\s*\|inputs\|/g)].length;
  if (rows.length !== invocations) {
    failures.push(
      `${RUNNERS_POLISH}: the runner pattern reads ${rows.length} of the ${invocations} polish runners, so the rest ` +
        `escape the POLISH_SIGNALS parity check; teach the pattern the new formatting`,
    );
  }
  for (const [, id, run] of rows) {
    const signal = signals.find((entry) => entry.run === run);
    if (signal === undefined || signal.id !== id || signal.readsStylesheets) {
      failures.push(
        `${RUNNERS_POLISH}: polish.${id} runs \`${run}\`, which is not the page-only POLISH_SIGNALS entry for ` +
          `${id}; a hosted runner must grade exactly what the CLI's polish phase grades`,
      );
    }
  }
  if (!RUNS_THE_TABLE.test(table)) {
    failures.push(
      `${POLISH_TABLE}: run_all_signals must map every POLISH_SIGNALS entry, or the CLI grades a ` +
        `different set of signals from the hosted polish runners`,
    );
  }
  for (const file of listFiles(RUNTIME_POLISH, (name) => name.endsWith(".rs"))) {
    if (SHADOW.test(code(read(file)))) {
      failures.push(
        `${file} defines its own polish runner, stylesheet counter, grade, table or sample limit, which shadows ` +
          `the engine's through the runtime's re-export, so the CLI would grade differently from the hosted runners`,
      );
    }
  }
  for (const phase of POLISH_PHASES) {
    const lines = code(read(phase));
    if (
      !/\brun_all_signals\(/.test(lines) ||
      !/\bpolish::polish_check_result\b/.test(lines) ||
      !/\bpolish::grade_stylesheet_coverage\s*\(/.test(lines)
    ) {
      failures.push(
        `${phase} must grade polish through the engine's run_all_signals over every POLISH_SIGNALS ` +
          `entry, convert with polish::polish_check_result and apply polish::grade_stylesheet_coverage, ` +
          `on code lines; otherwise the hosted ` +
          `polish runners grade what the CLI does not`,
      );
    }
  }
  return failures;
}
