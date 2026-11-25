export function desktopScannerBodySafetyFailures(read, extra = []) {
  const failures = [];
  const scannerFiles = [...extra, "apps/desktop/src-tauri/src/cli/lane.rs"];
  const unsafeReads = scannerFiles.filter((file) => {
    const source = read(file);
    return /\.text\s*\(\s*\)\s*\.await/.test(source) || /\.bytes\s*\(\s*\)\s*\.await/.test(source);
  });
  if (unsafeReads.length > 0) {
    failures.push(
      `scanner HTTP bodies must use http_client::read_body_limited: ${unsafeReads.join(", ")}`,
    );
  }

  const httpClient = read("apps/desktop/src-tauri/src/http_client.rs");
  if (
    !httpClient.includes("pub async fn read_body_limited") ||
    !httpClient.includes("while let Some(chunk) = response.chunk().await") ||
    !httpClient.includes("bounded_body_reader_rejects_oversized_chunked_response_before_eof")
  ) {
    failures.push(
      "the shared HTTP client must stream response bodies through a byte-counted reader with an oversized chunked-response regression test",
    );
  }

  const page = read("apps/desktop/src-tauri/crates/protocol/src/page.rs");
  if (!page.includes("self.body.to_ascii_lowercase()")) {
    failures.push(
      "HTML offset parsing must preserve UTF-8 byte positions and keep Unicode regression coverage",
    );
  }
  return failures;
}
