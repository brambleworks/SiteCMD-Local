export function rustlsCryptoProviderFailures(read, listFiles, extraRoots = []) {
  const failures = [];

  const rustFiles = ["apps/desktop/src-tauri/src", ...extraRoots].flatMap((dir) =>
    listFiles(dir, (file) => file.endsWith(".rs") && !/[/\\]tests?[/\\]/.test(file)),
  );

  // This matches only provider-less `builder()` calls after comments are
  // stripped, not `builder_with_provider(`.
  const stripLineComments = (src) => src.replace(/\/\/.*$/gm, "");
  const offenders = rustFiles.filter((file) =>
    /ClientConfig::builder\(\)/.test(stripLineComments(read(file))),
  );
  if (offenders.length > 0) {
    failures.push(
      `rustls ClientConfig must bind a crypto provider via builder_with_provider (the provider-less ClientConfig::builder() panics in headless/CLI scans where no process-default provider is installed, breaking the loopback TLS connection): ${offenders.join(", ")}`,
    );
  }

  return failures;
}
