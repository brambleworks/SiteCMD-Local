import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import {
  validateRepositoryFiles,
  validateRepositorySnapshot,
} from "../lib/repository-snapshot.mjs";
import { digest } from "../lib/workflow-plan.mjs";
import { createWorkspace, mountDesktopWorkspace, closeWorkspace } from "./trial-workspace.mjs";

const { cases, product } = JSON.parse(readFileSync(0, "utf8"));
if (
  !/^[a-f0-9]{40}$/.test(product?.commit ?? "") ||
  product.cli !== `/opt/sitecmd-benchmark/products/${product.commit}/sitecmd_cli` ||
  digest(readFileSync(product.cli)) !== product.cliSha256
)
  throw new Error("The installed scanner differs from its product receipt");

function variantSource(item, variant) {
  const snapshot = item[`${variant}Snapshot`];
  if (!snapshot) {
    const repositoryFiles = item[`${variant}RepositoryFiles`];
    if (repositoryFiles) {
      validateRepositoryFiles(repositoryFiles);
      return {
        files: Object.fromEntries(
          repositoryFiles.map((file) => [file.name, Buffer.from(file.base64, "base64")]),
        ),
        modes: Object.fromEntries(repositoryFiles.map((file) => [file.name, file.mode])),
      };
    }
    return { files: item[`${variant}Files`], modes: {} };
  }
  validateRepositorySnapshot(snapshot);
  return {
    files: Object.fromEntries(
      snapshot.files.map((file) => [file.name, Buffer.from(file.base64, "base64")]),
    ),
    modes: Object.fromEntries(snapshot.files.map((file) => [file.name, file.mode])),
  };
}

const results = [];
for (const item of cases) {
  const reports = {};
  const variants = item.upstreamSnapshot ? ["baseline", "upstream"] : ["baseline", "reference"];
  for (const variant of variants) {
    const id = randomBytes(16).toString("hex");
    const source = variantSource(item, variant);
    const workspace = createWorkspace(id, source.files, source.modes);
    let mounted;
    try {
      mounted = mountDesktopWorkspace(id, workspace);
      const result = spawnSync(
        "sudo",
        ["-u", "sitecmd", product.cli, "audit", mounted.path, "--format", "json"],
        { encoding: "utf8", timeout: 120000, maxBuffer: 16 * 1024 * 1024 },
      );
      if (result.status !== 0) throw new Error(`Code Scan failed: ${result.stderr}`);
      const report = JSON.parse(result.stdout);
      reports[variant] = { report, raw: result.stdout };
    } finally {
      try {
        mounted?.close();
      } finally {
        closeWorkspace(workspace);
      }
    }
  }
  results.push({ id: item.id, ...reports });
}
console.log(JSON.stringify(results));
