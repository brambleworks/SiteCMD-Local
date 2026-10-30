export const MCP_SERVER_VERSION = "2.0.0";

/** Desktop migration versions this server's SQL was written against; see apps/desktop/src-tauri/src/db/migrations.rs. */
export const SUPPORTED_SCHEMA_VERSIONS = { min: 30, max: 30 } as const;
