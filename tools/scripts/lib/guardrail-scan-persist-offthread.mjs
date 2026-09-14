import { stripNonCode } from "./guardrail-source-text.mjs";

const PERSISTENCE = [
  ["web_scan.rs", "post_scan_persist", "persist_scan_blocking"],
  ["multi_scan.rs", "scan_multi_for_execution", "persist_multi_page_blocking"],
];

/** Find the matching delimiter after comments and literals have been blanked. */
function closing(code, start, open, close) {
  let depth = 0;
  for (let index = start; index < code.length; index += 1) {
    if (code[index] === open) depth += 1;
    if (code[index] === close && --depth === 0) return index;
  }
  return -1;
}

function asyncBodies(code) {
  const functions = new Map();
  for (const match of code.matchAll(/\basync\s+fn\s+([a-zA-Z_]\w*)\s*[<(]/g)) {
    const start = code.indexOf("{", match.index + match[0].length);
    if (start === -1) continue;
    const end = closing(code, start, "{", "}");
    if (end !== -1) functions.set(match[1], code.slice(start + 1, end));
  }
  return functions;
}

function blockingCalls(body) {
  const ranges = [];
  for (const match of body.matchAll(/\bcrate\s*::\s*commands\s*::\s*run_blocking\s*\(/g)) {
    const start = body.indexOf("(", match.index);
    const end = closing(body, start, "(", ")");
    if (end !== -1 && /^\s*\.\s*await\b/.test(body.slice(end + 1))) {
      ranges.push([start, end]);
    }
  }
  return ranges;
}

/** Check real call placement; runtime tests still own executor behavior. */
export function scanPersistOffThreadFailures(read, exists) {
  const failures = [];
  for (const [name, entrypoint, persistence] of PERSISTENCE) {
    const file = `apps/desktop/src-tauri/src/commands/scan/${name}`;
    const fail = (detail) =>
      failures.push(`${file} - scan persistence must run off the async runtime: ${detail}.`);
    if (!exists(file)) {
      fail("required module is missing");
      continue;
    }
    const bodies = asyncBodies(stripNonCode(read(file), file));
    const entry = bodies.get(entrypoint);
    if (entry === undefined) {
      fail(`${entrypoint} is missing`);
      continue;
    }
    const persistenceCalls = [...entry.matchAll(new RegExp(`\\b${persistence}\\s*\\(`, "g"))];
    const blocks = blockingCalls(entry);
    if (
      !persistenceCalls.length ||
      persistenceCalls.some(
        (call) => !blocks.some(([start, end]) => call.index > start && call.index < end),
      )
    ) {
      fail(`${entrypoint} must call ${persistence} inside an awaited run_blocking closure`);
    }
    for (const [name, body] of bodies) {
      const blocks = blockingCalls(body);
      for (const call of body.matchAll(/\b(db\w*)\s*\.\s*(\w+)\s*\(/g)) {
        if (call[1] !== "db" && !call[1].startsWith("db_")) continue;
        if (["clone", "as_ref"].includes(call[2])) continue;
        if (!blocks.some(([start, end]) => call.index > start && call.index < end)) {
          fail(`${name} calls synchronous Database::${call[2]} outside run_blocking`);
        }
      }
    }
  }
  return failures;
}
