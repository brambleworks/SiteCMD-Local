import { describe, expect, it } from "vitest";
import { checkCategories } from "./lib/check-categories.mjs";

const SESSION = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";
const SESSION_IDS = [
  "seo.duplicate_title_across_pages",
  "seo.duplicate_description_across_pages",
  "seo.duplicate_h1",
  "seo.orphan_pages",
  "seo.noindex_in_sitemap",
  "seo.canonical_loop",
  "seo.hreflang_reciprocity",
];

function categoriesFrom(source) {
  return checkCategories(
    (file) => (file === SESSION ? source : ""),
    () => [],
  );
}

describe("session check categories", () => {
  it("maps every declared session id to seo", () => {
    const source = `
pub const SESSION_CHECK_IDS: &[&str] = &[
${SESSION_IDS.map((id) => `    "${id}",`).join("\n")}
];
fn base_result() { ScanCategory::Seo }
`;
    expect(categoriesFrom(source).categories).toEqual(
      Object.fromEntries(SESSION_IDS.map((id) => [id, "seo"])),
    );
  });

  it("rejects an empty session source", () => {
    expect(() => categoriesFrom("")).toThrow(
      `check-categories: ${SESSION} declares no SESSION_CHECK_IDS`,
    );
  });

  it("rejects a wrapper that re-exports the session ids", () => {
    const source = "pub use sitecmd_engine::session::{SessionSitemap, SESSION_CHECK_IDS};";
    expect(() => categoriesFrom(source)).toThrow(
      `check-categories: ${SESSION} declares no SESSION_CHECK_IDS`,
    );
  });
});
