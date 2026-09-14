import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../apps/desktop/src-tauri/crates/", import.meta.url));
const corpus = JSON.parse(
  readFileSync(path.join(root, "engine/fixtures/checks/golden.json"), "utf8"),
);
const output = path.join(root, "engine-fuzz/corpus");
for (const target of ["page_input", "sitemap_input", "evaluation_payload"]) {
  mkdirSync(path.join(output, target), { recursive: true });
}
for (const [index, item] of corpus.cases.entries()) {
  const name = `golden-${index}`;
  writeFileSync(path.join(output, "page_input", name), item.page.body);
  writeFileSync(path.join(output, "evaluation_payload", name), JSON.stringify({ page: item.page }));
}
for (const [index, body] of [
  "abcdefg😃",
  "Sitemap: https://example.com/sitemap.xml\n",
  "<urlset><url><loc>https://example.com</loc></url></urlset>",
  "<sitemapindex><sitemap><loc>https://example.com/child.xml</loc></sitemap></sitemapindex>",
  "<urlset><url><loc>&amp;</loc>",
].entries()) {
  writeFileSync(path.join(output, "sitemap_input", `seed-${index}`), body);
}
console.log(`Seeded engine fuzz corpora from ${corpus.cases.length} golden cases.`);
