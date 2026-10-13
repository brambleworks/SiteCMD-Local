import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

import { stripComments } from "./lib/guardrail-source-text.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const CHECKS = "apps/desktop/src-tauri/src/checks";
const SEAM = `${CHECKS}/probe_adapter.rs`;

// A reqwest RequestBuilder is executed with a no-argument `.send()`. Channel
// senders always carry a value, so the empty parentheses are what separate an
// HTTP request from a `tx.send(value)`.
const BUILDER_SEND = /\.send\(\s*\)/;

// Async checks run concurrently and every one of them can be handed a page
// with hundreds of same-origin targets, so an unbounded burst from any of
// them tears down the shared HTTP/2 connection every other check is using
// (see the PROBE_HOST_CONCURRENCY comment in constants.rs). The seam in
// probe_adapter.rs is what bounds that. These files predate it and each has a
// reason it cannot reproduce the burst; a new check does not, and belongs on
// the seam instead of on this list.
const DIRECT_SEND_EXEMPTIONS = new Map([
  ["performance/compression.rs", "reads the bodies it asks for"],
  ["performance/assets/measure.rs", "reads the bodies it asks for"],
  ["polish/css_fetch.rs", "reads the bodies it asks for"],
  ["performance/timing.rs", "measures TTFB and must not time seam queueing"],
  ["security/vulnerable_libraries.rs", "queries the OSV API, not the scanned origin"],
]);

function walk(relativeDir) {
  const files = [];
  for (const entry of fs.readdirSync(path.join(ROOT, relativeDir), { withFileTypes: true })) {
    const relativePath = `${relativeDir}/${entry.name}`;
    if (entry.isDirectory()) files.push(...walk(relativePath));
    else if (entry.name.endsWith(".rs")) files.push(relativePath);
  }
  return files;
}

/**
 * Holds every same-origin HTTP request under `src/checks` to the probe seam.
 *
 * `read` returns a file's source; `files` is the list of Rust files to judge.
 * Both are injected so the negative controls below can judge a synthetic tree.
 */
export function probeSeamFailures(read, files) {
  const failures = [];
  const seamDoc = read(SEAM);
  const sending = new Set();

  for (const file of files) {
    if (file === SEAM || /_tests?\.rs$/.test(file.split("/").pop())) continue;
    if (!BUILDER_SEND.test(stripComments(read(file), file))) continue;
    const relative = file.slice(`${CHECKS}/`.length);
    sending.add(relative);
    if (DIRECT_SEND_EXEMPTIONS.has(relative)) continue;
    failures.push(
      `${file} sends an HTTP request directly instead of through the probe seam. ` +
        `Build a ProbeRequest and call checks::probe (or probe_with_timeout) so the request ` +
        `counts against PROBE_HOST_CONCURRENCY for its origin.`,
    );
  }

  for (const [relative, reason] of DIRECT_SEND_EXEMPTIONS) {
    if (!sending.has(relative)) {
      failures.push(
        `${CHECKS}/${relative} no longer sends an HTTP request directly. ` +
          `Drop it from DIRECT_SEND_EXEMPTIONS in tools/scripts/guardrail-probe-seam.test.mjs ` +
          `so the exemption list stays the real list.`,
      );
      continue;
    }
    if (!seamDoc.includes(relative)) {
      failures.push(
        `${SEAM} does not name ${relative} (${reason}) among the checks that bypass the seam. ` +
          `The module doc has to match DIRECT_SEND_EXEMPTIONS or it claims more than it holds.`,
      );
    }
  }

  return failures;
}

const realRead = (file) => fs.readFileSync(path.join(ROOT, file), "utf8");
const realFiles = walk(CHECKS);

/** Reads from `overrides` first, so a control can add or replace one file. */
function overlay(overrides) {
  return {
    read: (file) => overrides.get(file) ?? realRead(file),
    files: [...new Set([...realFiles, ...overrides.keys()])],
  };
}

describe("the probe seam is the only way a check reaches an origin", () => {
  it("finds no unbounded sender under src/checks", () => {
    expect(probeSeamFailures(realRead, realFiles)).toEqual([]);
  });

  it("covers the whole check tree, not a sample", () => {
    expect(realFiles.length).toBeGreaterThan(40);
    expect(realFiles).toContain(SEAM);
  });

  it("rejects a new check that sends on the client directly", () => {
    const { read, files } = overlay(
      new Map([
        [
          `${CHECKS}/security/new_burst.rs`,
          "async fn run(client: &reqwest::Client) { let _ = client.get(url).send().await; }",
        ],
      ]),
    );
    expect(probeSeamFailures(read, files).join("\n")).toContain(
      "security/new_burst.rs sends an HTTP request directly",
    );
  });

  it("ignores a channel send, which is not an HTTP request", () => {
    const { read, files } = overlay(
      new Map([
        [
          `${CHECKS}/security/new_channel.rs`,
          "async fn run(tx: Sender<u8>) { let _ = tx.send(1).await; }",
        ],
      ]),
    );
    expect(probeSeamFailures(read, files)).toEqual([]);
  });

  it("ignores a send that only appears in a comment", () => {
    const { read, files } = overlay(
      new Map([
        [`${CHECKS}/security/new_comment.rs`, "// Never call client.get(url).send() here."],
      ]),
    );
    expect(probeSeamFailures(read, files)).toEqual([]);
  });

  it("rejects an exemption the seam's module doc does not name", () => {
    const { read, files } = overlay(
      new Map([[SEAM, realRead(SEAM).replace("polish/css_fetch.rs", "polish/other.rs")]]),
    );
    expect(probeSeamFailures(read, files).join("\n")).toContain(
      "does not name polish/css_fetch.rs",
    );
  });

  it("rejects an exemption that no longer sends anything", () => {
    const { read, files } = overlay(
      new Map([[`${CHECKS}/performance/timing.rs`, "async fn run() {}"]]),
    );
    expect(probeSeamFailures(read, files).join("\n")).toContain(
      "performance/timing.rs no longer sends an HTTP request directly",
    );
  });
});
