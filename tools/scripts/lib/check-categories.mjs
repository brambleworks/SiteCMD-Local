import { productionHalf, webCheckIdPrefixes, webCheckIdSources } from "./product-facts.mjs";
import { constList } from "./guardrail-engine-lane-parsing.mjs";

const SESSION_CHECKS = "apps/desktop/src-tauri/crates/engine/src/session/mod.rs";

const CATEGORY_BY_VARIANT = {
  Accessibility: "accessibility",
  Compliance: "compliance",
  Config: "config",
  Performance: "performance",
  Polish: "polish",
  Security: "security",
  Seo: "seo",
};

const DIRECTORY_CATEGORIES = new Set([
  "accessibility",
  "compliance",
  "performance",
  "security",
  "seo",
]);

function categoriesMentioned(source) {
  const found = new Set();
  for (const [, variant] of source.matchAll(/ScanCategory::(\w+)/g)) found.add(variant);
  return found;
}

function adjacentCategory(source, index) {
  const window = source.slice(index, index + 400);
  const match = window.match(/category: ScanCategory::(\w+)/);
  return match ? match[1] : null;
}

function traitImplCategories(source) {
  const resolved = new Map();
  const blocks = source.split(/\bimpl\b/);
  for (const block of blocks) {
    const id = block.match(/fn id\(&self\) -> &str \{\s*"([^"]+)"/);
    const category = block.match(/fn category\(&self\) -> ScanCategory \{\s*ScanCategory::(\w+)/);
    if (id && category) resolved.set(id[1], category[1]);
  }
  return resolved;
}

function resolveFile(file, source, ids, assign) {
  const mentioned = categoriesMentioned(source);
  if (mentioned.size === 1) {
    const [variant] = mentioned;
    for (const id of ids) assign(id, variant, file);
    return;
  }
  if (mentioned.size === 0) {
    const directory = file.split("/").at(-2);
    if (!DIRECTORY_CATEGORIES.has(directory)) {
      throw new Error(
        `check-categories: ${file} emits ${[...ids].join(", ")} but names no ScanCategory and sits outside the single-category directories`,
      );
    }
    const variant = directory[0].toUpperCase() + directory.slice(1);
    for (const id of ids) assign(id, variant, file);
    return;
  }
  const byImpl = traitImplCategories(source);
  const constNames = new Map(
    [...source.matchAll(/const ([A-Z_]+): &str = "([^"]+)"/g)].map(([, name, id]) => [id, name]),
  );
  // A shared builder is safe only when every parameterized emit agrees.
  const parameterized = new Set();
  for (const site of source.matchAll(/check_id: [a-z_][a-z0-9_]*\s*[.,]/g)) {
    const near = adjacentCategory(source, site.index);
    if (near !== null) parameterized.add(near);
  }
  for (const id of ids) {
    let variant = byImpl.get(id) ?? null;
    const emitForms = [`check_id: "${id}"`];
    const constName = constNames.get(id);
    if (constName) emitForms.push(`check_id: ${constName}`);
    for (const form of emitForms) {
      for (const site of source.matchAll(
        new RegExp(form.replaceAll(".", "\\.").replaceAll("(", "\\(").replaceAll(")", "\\)"), "g"),
      )) {
        const near = adjacentCategory(source, site.index);
        if (near === null || (variant !== null && near !== variant)) {
          throw new Error(
            `check-categories: ${file} mixes categories and '${id}' cannot be resolved per emit site`,
          );
        }
        variant = near;
      }
    }
    if (variant === null && parameterized.size === 1) {
      [variant] = parameterized;
    }
    if (variant === null) {
      throw new Error(
        `check-categories: ${file} mixes categories (${[...mentioned].join(", ")}) and '${id}' has no adjacent category`,
      );
    }
    assign(id, variant, file);
  }
}

/** Map exact checks and dynamic families to lowercase categories. */
export function checkCategories(read, listFiles) {
  const byId = new Map();
  const assign = (id, variant, file) => {
    const category = CATEGORY_BY_VARIANT[variant];
    if (!category) {
      throw new Error(`check-categories: ${file} names unknown ScanCategory::${variant}`);
    }
    const existing = byId.get(id);
    if (existing && existing !== category) {
      throw new Error(
        `check-categories: '${id}' resolves to both ${existing} and ${category}; emit sites disagree`,
      );
    }
    byId.set(id, category);
  };

  const idsByFile = new Map();
  for (const [id, files] of webCheckIdSources(read, listFiles)) {
    for (const file of files) {
      if (!idsByFile.has(file)) idsByFile.set(file, new Set());
      idsByFile.get(file).add(id);
    }
  }
  for (const [file, ids] of idsByFile) resolveFile(file, productionHalf(read(file)), ids, assign);

  const sessionSource = productionHalf(read(SESSION_CHECKS));
  const sessionIds = new Set(constList(sessionSource, "SESSION_CHECK_IDS") ?? []);
  if (sessionIds.size === 0) {
    throw new Error(`check-categories: ${SESSION_CHECKS} declares no SESSION_CHECK_IDS`);
  }
  resolveFile(SESSION_CHECKS, sessionSource, sessionIds, assign);

  const families = new Map();
  for (const [prefix, file] of webCheckIdPrefixes(read, listFiles)) {
    const source = productionHalf(read(file));
    const mentioned = categoriesMentioned(source);
    if (mentioned.size !== 1) {
      throw new Error(
        `check-categories: family prefix '${prefix}' in ${file} needs exactly one category, saw ${mentioned.size}`,
      );
    }
    const [variant] = mentioned;
    const category = CATEGORY_BY_VARIANT[variant];
    if (!category) {
      throw new Error(`check-categories: ${file} names unknown ScanCategory::${variant}`);
    }
    families.set(prefix, category);
  }

  return {
    categories: Object.fromEntries([...byId.entries()].sort(([a], [b]) => a.localeCompare(b))),
    families: Object.fromEntries([...families.entries()].sort(([a], [b]) => a.localeCompare(b))),
    schema_version: 1,
  };
}
