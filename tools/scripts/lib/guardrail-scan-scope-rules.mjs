const ENGINE_ROUTE = "apps/desktop/src-tauri/crates/protocol/src/route.rs";

export function scanScopeFailures(read) {
  const failures = [];

  const route = read(ENGINE_ROUTE);
  if (!/pub const CANONICALIZER_VERSION/.test(route)) {
    failures.push(
      `${ENGINE_ROUTE} must keep CANONICALIZER_VERSION: a change to the route rules is a new version through the compatibility gate, not an edit to the old one.`,
    );
  }

  return failures;
}
