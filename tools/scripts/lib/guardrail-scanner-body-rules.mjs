export function desktopScannerBodySafetyFailures(read, listFiles) {
  const failures = [];
  const scannerFiles = [
    ...listFiles("apps/desktop/src-tauri/src/checks", (file) => file.endsWith(".rs")),
    ...listFiles("apps/desktop/src-tauri/crates/engine/src/checks", (file) => file.endsWith(".rs")),
    "apps/desktop/src-tauri/src/core/scanner.rs",
    "apps/desktop/src-tauri/src/core/scanner/verify.rs",
    "apps/desktop/src-tauri/src/core/sitemap.rs",
  ];
  const unsafeReads = scannerFiles.filter((file) => {
    const source = read(file);
    return /\.text\s*\(\s*\)\s*\.await/.test(source) || /\.bytes\s*\(\s*\)\s*\.await/.test(source);
  });
  if (unsafeReads.length > 0) {
    failures.push(
      `scanner HTTP bodies must use http_client::read_body_limited/read_text_limited: ${unsafeReads.join(", ")}`,
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

  // Extract page signals before the polish phase consumes the body. Both
  // anchors tolerate rustfmt wrapping the call across lines, so a formatting
  // change can never fail this rule with an ordering message.
  const scanner = read("apps/desktop/src-tauri/src/core/scanner.rs");
  const preRead = scanner.match(/site_facts::read_before_polish\s*\(/);
  const polish = scanner.match(/run_polish_phase\s*\(\s*&mut\s+ctx/);
  if (!preRead || !polish || preRead.index > polish.index) {
    failures.push(
      "scanner.rs must call site_facts::read_before_polish before run_polish_phase consumes the page body via mem::take",
    );
  }
  const siteFacts = read("apps/desktop/src-tauri/src/core/scanner/site_facts.rs");
  if (!siteFacts.includes("extract_page_signals_with_headers(")) {
    failures.push(
      "site_facts::read_before_polish must extract page_signals (extract_page_signals_with_headers); a body read that happens anywhere else can be moved after the polish take without anything noticing",
    );
  }

  const page = read("apps/desktop/src-tauri/crates/engine/src/page.rs");
  const exposedFiles = read(
    "apps/desktop/src-tauri/crates/engine/src/checks/security/exposed_files.rs",
  );
  const stackTests = read("apps/desktop/src-tauri/crates/engine/src/stack_tests.rs");
  if (
    !page.includes("self.body.to_ascii_lowercase()") ||
    !exposedFiles.includes("script_extraction_preserves_offsets_after_unicode_case_expansion") ||
    !exposedFiles.includes("secret_snippet_uses_valid_unicode_boundaries") ||
    !stackTests.includes("generator_detection_preserves_offsets_after_unicode_case_expansion")
  ) {
    failures.push(
      "HTML offset parsing must preserve UTF-8 byte positions and keep Unicode regression coverage",
    );
  }

  return failures;
}
