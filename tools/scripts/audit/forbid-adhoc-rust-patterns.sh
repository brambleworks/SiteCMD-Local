#!/usr/bin/env bash
# Enforce shared HTTP clients and sanitized command errors.
set -e

SRC="apps/desktop/src-tauri/src"

# A missing source tree must not look like a successful no-match.
for dir in "$SRC/cli" "$SRC/core" "$SRC/db"; do
  if [ ! -d "$dir" ]; then
    echo "forbid-adhoc-rust-patterns: scanned directory missing: $dir (moved? update this script)" >&2
    exit 2
  fi
done

# Only Rust sources count; the guides beside them quote these patterns.
# HTTP in these modules must use the shared http_client.
violations=$(grep -rnE --include='*.rs' "reqwest::Client::(new|builder)|reqwest::ClientBuilder::new|(^|[^A-Za-z0-9_:])Client::(new|builder)\(|(^|[^A-Za-z0-9_:])ClientBuilder::new\(" \
  "$SRC/cli" "$SRC/core" 2>/dev/null | grep -v "allow-ad-hoc-client" || true)
if [ -n "$violations" ]; then
  echo "Direct reqwest::Client construction is forbidden -- use the shared http_client:"
  echo "$violations"
  exit 1
fi

# Production command errors must be sanitized; the DB layer keeps typed errors.
error_violations=""
while IFS= read -r f; do
  # Ignore inline test modules by tracking their brace depth.
  offending=$(awk '
    {
      if (!in_test) {
        if (/^[[:space:]]*#\[cfg\(test\)\]/) { test_attr_pending = 1; next }
        if (test_attr_pending && /^[[:space:]]*mod[[:space:]]+[A-Za-z_]/) {
          in_test = 1; depth = 0; test_attr_pending = 0;
        } else { test_attr_pending = 0 }
      }
      if (in_test) {
        for (i = 1; i <= length($0); i++) {
          c = substr($0, i, 1)
          if (c == "{") depth++
          else if (c == "}") { depth--; if (depth == 0) { in_test = 0; break } }
        }
        next
      }
      if (/map_err\(\|e\| e\.to_string\(\)\)/) print FILENAME ":" NR ":" $0
    }
  ' "$f")
  if [ -n "$offending" ]; then
    error_violations="${error_violations}${offending}\n"
  fi
done < <(grep -rln --include='*.rs' "map_err(|e| e\.to_string())" "$SRC/cli" "$SRC/db" 2>/dev/null \
  | grep -vE '(_tests\.rs|/tests\.rs|/test_helpers\.rs)$')
if [ -n "$error_violations" ]; then
  echo "Raw '.map_err(|e| e.to_string())' is forbidden in commands (use sanitize_error) and in the db layer (return DbError via ?):"
  printf "%b" "$error_violations"
  exit 1
fi
