import { rmSync } from "node:fs";

export function confirmatoryWorkflowStatePaths(sessionId, state) {
  if (!/^[a-f0-9]{32}$/.test(sessionId ?? "")) {
    throw new Error("Confirmatory workflow cleanup requires a valid session identity");
  }
  const expected = {
    workspace: `/srv/sitecmd-benchmark/workspaces/${sessionId}`,
    mounted: `/home/sitecmd/projects/${sessionId}`,
    data: `/srv/sitecmd-benchmark/app-data/${sessionId}`,
  };
  for (const [name, value] of Object.entries(state)) {
    if (!Object.hasOwn(expected, name) || (value !== undefined && value !== expected[name])) {
      throw new Error(`Confirmatory workflow cleanup rejected its ${name} path`);
    }
  }
  return Object.values(state).filter((value) => value !== undefined);
}

export function removeConfirmatoryWorkflowState(sessionId, state, remove = rmSync) {
  const targets = confirmatoryWorkflowStatePaths(sessionId, state);
  for (const target of targets) remove(target, { recursive: true, force: true });
}
