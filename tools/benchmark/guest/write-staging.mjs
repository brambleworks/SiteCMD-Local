import { spawnSync } from "node:child_process";
import {
  chownSync,
  closeSync,
  constants,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
} from "node:fs";
import path from "node:path";
import { systemCommand } from "./desktop-session.mjs";

function directoryInfo(directory, uid) {
  const info = lstatSync(directory);
  if (!info.isDirectory() || info.uid !== uid)
    throw new Error("Unsafe Claude write-staging directory");
  return info;
}

function aclCommand(command, args, directory, identity) {
  const fd = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try {
    const info = fstatSync(fd);
    if (info.dev !== identity.dev || info.ino !== identity.ino || info.uid !== identity.uid)
      throw new Error("Claude write-staging directory changed");
    // Pass the checked directory descriptor, not an agent-replaceable pathname.
    const result = spawnSync(command, [...args, "/proc/self/fd/3"], {
      stdio: ["ignore", "pipe", "pipe", fd],
      encoding: "utf8",
      timeout: 10000,
      maxBuffer: 4096,
    });
    if (result.status !== 0)
      throw new Error(
        `Write-staging ACL command failed: ${result.error?.message || result.stderr}`,
      );
    return result.stdout.trim();
  } finally {
    closeSync(fd);
  }
}

export function prepareWriteStaging(workspace) {
  if (process.platform !== "linux" || process.getuid() !== 0)
    throw new Error("Write-staging preparation requires the guest controller");
  const uid = Number(systemCommand("id", ["-u", "runner"]));
  const gid = Number(systemCommand("id", ["-g", "runner"]));
  const readerUid = Number(systemCommand("id", ["-u", "sitecmd"]));
  directoryInfo(workspace, uid);
  const parent = path.join(workspace, ".claude");
  const directory = path.join(parent, ".cc-writes");
  for (const [target, mode] of [
    [parent, 0o755],
    [directory, 0o700],
  ]) {
    try {
      mkdirSync(target, { mode });
      chownSync(target, uid, gid);
    } catch (error) {
      if (error.code !== "EEXIST") throw error;
    }
    directoryInfo(target, uid);
  }
  if (readdirSync(directory).length)
    throw new Error("Claude write-staging directory is not empty before the first prompt");
  const parentIdentity = directoryInfo(parent, uid);
  const identity = directoryInfo(directory, uid);
  const expected = ["user::rwx", `user:${readerUid}:r-x`, "group::---", "mask::r-x", "other::---"];
  aclCommand("/usr/bin/setfacl", [`--set=${expected.join(",")}`], parent, parentIdentity);
  aclCommand("/usr/bin/setfacl", [`--set=${expected.join(",")}`], directory, identity);
  const verify = () => {
    const currentParent = directoryInfo(parent, uid);
    if (currentParent.dev !== parentIdentity.dev || currentParent.ino !== parentIdentity.ino)
      throw new Error("Claude write-staging parent changed");
    directoryInfo(directory, uid);
    for (const [target, info] of [
      [parent, parentIdentity],
      [directory, identity],
    ]) {
      const actual = aclCommand("/usr/bin/getfacl", ["--omit-header", "--numeric"], target, info);
      if (actual.split("\n").sort().join("\n") !== expected.toSorted().join("\n"))
        throw new Error("Claude write-staging permissions changed; pause the benchmark");
    }
  };
  verify();
  return {
    verify,
    receipt: {
      path: ".claude/.cc-writes",
      writer: "runner",
      reader: "sitecmd",
      access: "read-only",
    },
  };
}
