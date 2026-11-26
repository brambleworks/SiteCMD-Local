import fs from "node:fs";
import path from "node:path";

/** Overlay value marking a path the mutation removed. */
export const OVERLAY_DELETED = Symbol("overlay-deleted");

// Mirror directories ignored by the real runner.
const IGNORED_DIRECTORIES = new Set([".git", "node_modules", "dist", "target"]);

// Per-root caches use relative paths and remain valid for read-only test runs.
const treeCaches = new Map();

function treeCache(root) {
  let caches = treeCaches.get(root);
  if (!caches) {
    caches = { files: new Map(), dirents: new Map(), exists: new Map(), walks: new Map() };
    treeCaches.set(root, caches);
  }
  return caches;
}

function cachedRead(caches, root, relativePath) {
  let contents = caches.files.get(relativePath);
  if (contents === undefined) {
    contents = fs.readFileSync(path.join(root, relativePath), "utf8");
    caches.files.set(relativePath, contents);
  }
  return contents;
}

function cachedExists(caches, root, relativePath) {
  let present = caches.exists.get(relativePath);
  if (present === undefined) {
    present = fs.existsSync(path.join(root, relativePath));
    caches.exists.set(relativePath, present);
  }
  return present;
}

// Cached directory entries, or null for an absent directory.
function cachedEntries(caches, root, relativePath) {
  let entries = caches.dirents.get(relativePath);
  if (entries === undefined) {
    try {
      entries = fs
        .readdirSync(path.join(root, relativePath), { withFileTypes: true })
        .map((entry) => ({ name: entry.name, isDirectory: entry.isDirectory() }));
    } catch {
      entries = null;
    }
    caches.dirents.set(relativePath, entries);
  }
  return entries;
}

// Cache the unfiltered walk shared by all rule predicates.
function cachedWalk(caches, root, dir) {
  let files = caches.walks.get(dir);
  if (files === undefined) {
    files = [];
    const entries = cachedEntries(caches, root, dir);
    if (entries === null) {
      caches.walks.set(dir, null);
      return null;
    }
    for (const entry of entries) {
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;
      const relativePath = path.join(dir, entry.name);
      if (entry.isDirectory) files.push(...(cachedWalk(caches, root, relativePath) ?? []));
      else files.push(relativePath);
    }
    caches.walks.set(dir, files);
  }
  return files;
}

// Add synthetic ancestors for overlay files not present on disk.
function syntheticEntries(overlay) {
  const byDirectory = new Map();
  for (const [relativePath, value] of overlay) {
    if (value === OVERLAY_DELETED) continue;
    let name = path.posix.basename(relativePath);
    let parent = path.posix.dirname(relativePath);
    let isDirectory = false;
    while (name !== "" && name !== ".") {
      const bucket = byDirectory.get(parent) ?? new Map();
      bucket.set(name, isDirectory);
      byDirectory.set(parent, bucket);
      if (parent === "." || parent === "") break;
      name = path.posix.basename(parent);
      parent = path.posix.dirname(parent);
      isDirectory = true;
    }
  }
  return byDirectory;
}

/** Build guardrail I/O accessors over a repository root and optional overlay. */
export function overlayIo(root, overlay = new Map()) {
  const caches = treeCache(root);
  const added = syntheticEntries(overlay);
  // Reuse cached walks unless the overlay adds or removes a path.
  const addsPaths = [...overlay].some(
    ([relativePath, value]) =>
      value !== OVERLAY_DELETED && !cachedExists(caches, root, relativePath),
  );
  const hidesPaths = [...overlay.values()].some((value) => value === OVERLAY_DELETED);

  const read = (relativePath) => {
    const override = overlay.get(relativePath);
    if (override === OVERLAY_DELETED) {
      const error = new Error(`ENOENT: no such file or directory, open '${relativePath}'`);
      error.code = "ENOENT";
      throw error;
    }
    return override ?? cachedRead(caches, root, relativePath);
  };

  const exists = (relativePath) => {
    const override = overlay.get(relativePath);
    if (override !== undefined) return override !== OVERLAY_DELETED;
    // Added files make their synthetic parent directories observable.
    if (added.has(relativePath)) return true;
    return cachedExists(caches, root, relativePath);
  };

  // Rewalk only directories affected by the overlay.
  const walkFiles = (dir, predicate, files = []) => {
    const real = cachedEntries(caches, root, dir);
    const synthetic = added.get(dir);
    if (real === null && synthetic === undefined) {
      const error = new Error(`ENOENT: no such file or directory, scandir '${dir}'`);
      error.code = "ENOENT";
      throw error;
    }
    const entries = [...(real ?? [])];
    const seen = new Set(entries.map((entry) => entry.name));
    for (const [name, isDirectory] of synthetic ?? []) {
      if (!seen.has(name)) entries.push({ name, isDirectory });
    }
    for (const entry of entries) {
      if (IGNORED_DIRECTORIES.has(entry.name)) continue;
      const relativePath = path.join(dir, entry.name);
      if (entry.isDirectory) {
        walkFiles(relativePath, predicate, files);
      } else if (overlay.get(relativePath) !== OVERLAY_DELETED && predicate(relativePath)) {
        files.push(relativePath);
      }
    }
    return files;
  };

  const listFiles = (dir, predicate, files = []) => {
    const normalized = dir.replace(/\/+$/, "");
    if (addsPaths) return walkFiles(normalized, predicate, files);
    const walked = cachedWalk(caches, root, normalized);
    if (walked === null) {
      const error = new Error(`ENOENT: no such file or directory, scandir '${normalized}'`);
      error.code = "ENOENT";
      throw error;
    }
    for (const relativePath of walked) {
      if (hidesPaths && overlay.get(relativePath) === OVERLAY_DELETED) continue;
      if (predicate(relativePath)) files.push(relativePath);
    }
    return files;
  };

  const readJson = (relativePath) => JSON.parse(read(relativePath));

  return { root, read, readJson, exists, listFiles };
}
