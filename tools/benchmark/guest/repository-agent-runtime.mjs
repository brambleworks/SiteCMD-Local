import { cpSync, lchownSync, lstatSync, mkdirSync, readdirSync } from "node:fs";
import path from "node:path";

function setOwner(target, owner) {
  const stat = lstatSync(target);
  lchownSync(target, owner.uid, owner.gid);
  if (stat.isDirectory())
    for (const name of readdirSync(target)) setOwner(path.join(target, name), owner);
}

export function prepareRepositoryAgentRuntime({ item, workspace, channel, owner }) {
  if (!item.repositoryRuntime) return null;
  if (item.id === "onekey-http-client-tls-verification") return null;
  if (item.id !== "whoogle-named-config-path")
    throw new Error(`Unsupported repository agent runtime: ${item.id}`);
  const id = path.basename(workspace);
  if (!/^[a-f0-9]{24}$/.test(id) || path.basename(channel) !== id)
    throw new Error("Repository agent runtime requires matching trial paths");
  if (!Number.isSafeInteger(owner?.uid) || !Number.isSafeInteger(owner?.gid))
    throw new Error("Repository agent runtime requires an explicit owner");
  const directory = path.join(channel, "runtime");
  mkdirSync(directory, { mode: 0o700 });
  cpSync(path.join(workspace, "app", "static"), path.join(directory, "static"), {
    recursive: true,
    dereference: false,
  });
  mkdirSync(path.join(directory, "config"), { mode: 0o700 });
  setOwner(directory, owner);
  return { directory };
}
