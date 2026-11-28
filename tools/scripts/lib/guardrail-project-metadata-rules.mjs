import { functionBodyContains } from "./guardrail-rust-function.mjs";

export function projectMetadataReadFailures(read, sourceFiles = []) {
  const native = "apps/desktop/src-tauri/src/core";
  const safeFs = read(`${native}/safe_fs.rs`);
  const listing = read(`${native}/project_listing.rs`);
  const metadataReader = read(`${native}/engine_facts/inventory.rs`);
  const projectDetectionSources = [...sourceFiles.map(read), metadataReader];
  const usesGuardedProjectMetadataReads =
    functionBodyContains(safeFs, "read_project_path", "read_file_nofollow(") &&
    functionBodyContains(safeFs, "read_file_nofollow", "read_file_limited(&mut file, limit)") &&
    functionBodyContains(
      listing,
      "read_relative_file",
      "read_project_path(&self.dir, path, limit)",
    ) &&
    metadataReader.includes("listing.read_relative_file(&target, limit)") &&
    metadataReader.includes("read_project_path(directory, Path::new(name), limit)") &&
    projectDetectionSources.every(usesGuardedMetadataReads);

  return usesGuardedProjectMetadataReads
    ? []
    : ["Project detection must use shared bounded reads for repository-controlled metadata."];
}

export function usesGuardedMetadataReads(source) {
  return !/\bfs::read\(/.test(source) && !source.includes("fs::read_to_string");
}
