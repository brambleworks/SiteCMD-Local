// Dependency manifest and lockfile reads can bypass the shared byte limit.
export function nativeUpdateInventoryFailures(read, extraFiles = []) {
  const failures = [];
  const dependencyParserFiles = [
    ...extraFiles,
    // Apply the bounded-read guarantee to lockfile and workspace parsers.
    "apps/desktop/src-tauri/src/core/engine_facts/npm.rs",
  ];
  const unboundedDependencyReaders = dependencyParserFiles.filter((file) =>
    read(file).includes("read_to_string"),
  );
  const host = read("apps/desktop/src-tauri/crates/engine-host/src/wants.rs");
  if (
    !host.includes("let cap = if dependency {\n        MAX_DEPENDENCY_FILE_BYTES") ||
    !host.includes("let limit = if dependency {\n        cap") ||
    !host.includes("let bytes = read(limit)") ||
    unboundedDependencyReaders.length > 0
  ) {
    failures.push(
      `Dependency manifests and lockfiles must use the engine host dependency read limit so project-controlled files stay within the shared byte budget: ${unboundedDependencyReaders.join(", ")}`,
    );
  }

  return failures;
}
