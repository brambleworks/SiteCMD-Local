export const VERSION_FILES = [
  {
    file: "apps/desktop/package.json",
    read: (s) => s.match(/"version": "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/"version": "[^"]+"/, `"version": "${v}"`),
  },
  {
    file: "apps/desktop/src-tauri/tauri.conf.json",
    read: (s) => s.match(/"version": "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/"version": "[^"]+"/, `"version": "${v}"`),
  },
  {
    file: "apps/desktop/src-tauri/Cargo.toml",
    read: (s) => s.match(/^\[package\][\s\S]*?\nversion = "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/^(version = ")[^"]+(")/m, `$1${v}$2`),
  },
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
      const app = s.match(/name = "sitecmd"\nversion = "([^"]+)"/)?.[1];
      const cli = s.match(/name = "sitecmd-cli"\nversion = "([^"]+)"/)?.[1];
      const runtime = s.match(/name = "sitecmd-runtime"\nversion = "([^"]+)"/)?.[1];
      return app && app === cli && app === runtime ? app : undefined;
    },
    write: (s, v) =>
      s
        .replace(/(name = "sitecmd"\nversion = ")[^"]+(")/, `$1${v}$2`)
        .replace(/(name = "sitecmd-cli"\nversion = ")[^"]+(")/, `$1${v}$2`)
        .replace(/(name = "sitecmd-runtime"\nversion = ")[^"]+(")/, `$1${v}$2`),
  },
  {
    file: "apps/mcp-server/package.json",
    read: (s) => s.match(/"version": "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/"version": "[^"]+"/, `"version": "${v}"`),
  },
  {
    file: "apps/mcp-server/src/version.ts",
    read: (s) => s.match(/MCP_SERVER_VERSION = "([^"]+)"/)?.[1],
    write: (s, v) => s.replace(/MCP_SERVER_VERSION = "[^"]+"/, `MCP_SERVER_VERSION = "${v}"`),
  },
];
