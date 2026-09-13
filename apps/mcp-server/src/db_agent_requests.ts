import { getDb, getDbWrite, withBusyRetry } from "./db_connection.js";

// The only MCP module allowed to insert rows: one queue table the desktop watcher fulfils.

export interface AgentRequestInput {
  kind: "start_fix" | "run_scan";
  projectId: number;
  envUrl: string;
  checkId?: string;
  target?: { relativePath: string; line: number | null };
  scope?: "web" | "code" | "full";
  agentTool: string;
}

export interface AgentRequestRow {
  id: number;
  kind: string;
  status: string;
  result_json: string | null;
  failure_detail: string | null;
  created_at: number;
  updated_at: number;
}

/** Lowercase a URL's scheme and host while preserving path, query, and fragment. Mirrors the desktop's lowercase_origin. */
function lowercaseOrigin(url: string): string {
  const schemeEnd = url.indexOf("://");
  if (schemeEnd === -1) return url;
  const afterScheme = schemeEnd + 3;
  const rest = url.slice(afterScheme);
  const hostEndMatch = /[/?#]/.exec(rest);
  const hostEnd = hostEndMatch ? hostEndMatch.index : rest.length;
  return (
    url.slice(0, afterScheme).toLowerCase() +
    rest.slice(0, hostEnd).toLowerCase() +
    rest.slice(hostEnd)
  );
}

/** Mirrors the desktop's normalize_env_url so the watcher's environment lookup matches. */
export function normalizeEnvUrl(url: string): string {
  return lowercaseOrigin(url.replace(/\/+$/, ""));
}

export function createAgentRequest(input: AgentRequestInput): number {
  const now = Date.now();
  const info = getDbWrite()
    .prepare(
      `INSERT INTO agent_requests (kind, project_id, env_url, check_id, scope, agent_tool, status, created_at, updated_at,
                                  target_relative_path, target_line)
       VALUES (?, ?, ?, ?, ?, ?, 'requested', ?, ?, ?, ?)`,
    )
    .run(
      input.kind,
      input.projectId,
      normalizeEnvUrl(input.envUrl),
      input.checkId ?? null,
      input.scope ?? null,
      input.agentTool,
      now,
      now,
      input.target?.relativePath ?? null,
      input.target?.line ?? null,
    );
  return Number(info.lastInsertRowid);
}

export function getAgentRequest(id: number): AgentRequestRow | null {
  const row = getDb()
    .prepare(
      `SELECT id, kind, status, result_json, failure_detail, created_at, updated_at FROM agent_requests WHERE id = ?`,
    )
    .get(id) as AgentRequestRow | undefined;
  return row ?? null;
}

const POLL_MS = 250;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The stdio server handles one call at a time, so waiting here is the honest
 * choice; the wait must stay a real (setTimeout-based) async wait rather than
 * a synchronous Atomics.wait block, because the latter halts the whole
 * process's event loop, including its own timers, for the entire poll.
 */
export async function waitForAgentRequest(
  id: number,
  timeoutMs: number,
): Promise<AgentRequestRow | null> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const row = withBusyRetry(() => getAgentRequest(id));
    if (row && row.status !== "requested" && row.status !== "running") return row;
    await sleep(POLL_MS);
  }
  return withBusyRetry(() => getAgentRequest(id));
}
