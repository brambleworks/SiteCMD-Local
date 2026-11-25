export function projectMetadataReadFailures(read, sourceFiles = []) {
  const native = "apps/desktop/src-tauri/src/core";
  const safeFs = read(`${native}/safe_fs.rs`);
  const metadataReader = read(`${native}/engine_facts/inventory.rs`);
  const projectDetectionSources = [...sourceFiles.map(read), metadataReader];
  const usesGuardedProjectMetadataReads =
    safeFs.includes("pub(crate) fn read_bounded_file_under_root") &&
    safeFs.includes("pub(crate) fn read_bounded_text_under_root") &&
    metadataReader.includes("read_project_path(directory, Path::new(name), limit)") &&
    projectDetectionSources.every(usesGuardedMetadataReads);

  return usesGuardedProjectMetadataReads
    ? []
    : ["Project detection must use shared bounded reads for repository-controlled metadata."];
}

export function usesGuardedMetadataReads(source) {
  return !/\bfs::read\(/.test(source) && !source.includes("fs::read_to_string");
}
