import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { scanPersistOffThreadFailures } from "./lib/guardrail-scan-persist-offthread.mjs";

const FILE = "apps/desktop/src-tauri/src/commands/scan/web_scan.rs";
const VALID = `async fn post_scan_persist() {
  crate::commands::run_blocking(move || {
    db.find_project_for_url_result(url);
    persist_scan_blocking();
  }).await;
}`;
function failures(source) {
  return scanPersistOffThreadFailures(
    (file) => (file === FILE ? source : readFileSync(file, "utf8")),
    () => true,
  );
}

describe("scan persistence call placement", () => {
  it("accepts the checked-in asynchronous persistence paths", () => {
    expect(
      scanPersistOffThreadFailures(
        (file) => readFileSync(file, "utf8"),
        () => true,
      ),
    ).toEqual([]);
  });
  it("accepts awaited persistence and lookup inside the blocking closure", () => {
    expect(failures(VALID)).toEqual([]);
  });
  it.each([
    "// run_blocking( persist_scan_blocking(\nasync fn post_scan_persist() {}",
    'async fn post_scan_persist() { let text = "run_blocking( persist_scan_blocking("; }',
    'async fn post_scan_persist() { let text = r###"run_blocking( persist_scan_blocking("###; }',
    "/* outer /* run_blocking( */ persist_scan_blocking( */ async fn post_scan_persist() {}",
    "async fn unrelated() { crate::commands::run_blocking(move || persist_scan_blocking()).await; }\nasync fn post_scan_persist() {}",
    "async fn post_scan_persist() { crate::commands::run_blocking(move || 1).await; persist_scan_blocking(); }",
    VALID.replace(".await", ""),
  ])("rejects markers that do not place persistence in awaited blocking work", (source) => {
    expect(failures(source).join("\n")).toContain(
      "must call persist_scan_blocking inside an awaited",
    );
  });
  it("rejects a database lookup outside the closure even when persistence is wrapped", () => {
    const source = VALID.replace(
      "async fn post_scan_persist() {",
      "async fn post_scan_persist() { db.find_project_for_url_result(url);",
    );
    expect(failures(source).join("\n")).toContain("Database::find_project_for_url_result outside");
  });
  it("accepts formatting and comments between call tokens", () => {
    expect(failures(VALID.replace("run_blocking(", "run_blocking /* work */ ("))).toEqual([]);
  });
  it("checks cloned database handles without treating unrelated db-prefixed names as handles", () => {
    expect(failures(VALID.replace("db.find_project", "db_block.find_project"))).toEqual([]);
    expect(
      failures(
        VALID.replace(
          "async fn post_scan_persist() {",
          "async fn post_scan_persist() { dbsettings.load();",
        ),
      ),
    ).toEqual([]);
    expect(
      failures(
        VALID.replace(
          "async fn post_scan_persist() {",
          "async fn post_scan_persist() { db_block.load();",
        ),
      ).join("\n"),
    ).toContain("Database::load outside");
  });
  it("fails when a required persistence module disappears", () => {
    expect(
      scanPersistOffThreadFailures(
        () => "",
        () => false,
      ),
    ).toHaveLength(2);
  });
});
