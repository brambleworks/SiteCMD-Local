export const VERSION_FILES = [
  {
    file: "apps/desktop/src-tauri/crates/cli/Cargo.toml",
    read: (s) => s.match(/^\[package\][\s\S]*?\nversion = "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/^(version = ")[^"]+(")/m, `$1${v}$2`),
  },
  {
    file: "apps/desktop/src-tauri/crates/runtime/Cargo.toml",
    read: (s) => s.match(/^\[package\][\s\S]*?\nversion = "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/^(version = ")[^"]+(")/m, `$1${v}$2`),
  },
  {
    file: "apps/desktop/src-tauri/Cargo.lock",
    read: (s) => {
      const cli = s.match(/name = "sitecmd-cli"\nversion = "([^"]+)"/)?.[1];
      const runtime = s.match(/name = "sitecmd-runtime"\nversion = "([^"]+)"/)?.[1];
      return cli && cli === runtime ? cli : undefined;
    },
    write: (s, v) =>
      s
        .replace(/(name = "sitecmd-cli"\nversion = ")[^"]+(")/, `$1${v}$2`)
        .replace(/(name = "sitecmd-runtime"\nversion = ")[^"]+(")/, `$1${v}$2`),
  },
];
