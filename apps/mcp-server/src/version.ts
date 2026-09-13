export const MCP_SERVER_VERSION = "1.3.0";

/** Desktop migration versions this server's SQL was written against; see apps/desktop/src-tauri/src/db/migrations.rs. */
export const SUPPORTED_SCHEMA_VERSIONS = { min: 30, max: 30 } as const;
