# Naming Conventions

Names should make a file's role obvious before you open it. Avoid mixed
`camelCase`, `kebab-case`, and `PascalCase` for the same kind of file.

- Use `snake_case.rs` for Rust modules. Name sibling test files for the module
  they exercise, for example `signal_mapping_tests.rs` for `signal_mapping.rs`.
- Use `kebab-case.mjs` for Node tooling and `.test.mjs` for its tests, for example
  `check-budget-ratchet.mjs` and `check-budget-ratchet.test.mjs`.
- Preserve the names of public CLI commands, serialized fields, and persisted
  data keys when renaming files.
