import assert from "node:assert/strict";
import { createWriteStream } from "node:fs";
import { access, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath, pathToFileURL } from "node:url";
import { startNativeDesktop } from "./lib/native-webdriver.mjs";

if (process.platform !== "linux")
  throw new Error("Run the native smoke test on Linux under Xvfb and D-Bus.");
const root = fileURLToPath(new URL("../../", import.meta.url));
const requireMcp = createRequire(new URL("../../apps/mcp-server/package.json", import.meta.url));
const { Client } = await import(
  pathToFileURL(requireMcp.resolve("@modelcontextprotocol/sdk/client/index.js"))
);
const { StdioClientTransport } = await import(
  pathToFileURL(requireMcp.resolve("@modelcontextprotocol/sdk/client/stdio.js"))
);
const binary = path.resolve(
  process.env.SITECMD_SMOKE_BINARY ??
    path.join(root, "apps/desktop/src-tauri/target/debug/sitecmd"),
);
const bundle = path.resolve(
  process.env.SITECMD_SMOKE_MCP ?? path.join(root, "apps/mcp-server/dist-bundle/sitecmd-mcp.mjs"),
);
await Promise.all([access(binary), access(bundle)]);
const artifacts = path.join(root, ".artifacts/native-smoke");
await mkdir(artifacts, { recursive: true });
const scratch = await mkdtemp(path.join(artifacts, "run-"));
const source = path.join(scratch, "project/src");
await mkdir(source, { recursive: true });
await writeFile(path.join(source, "index.js"), 'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n');
await writeFile(
  path.join(source, "../package.json"),
  '{"name":"native-smoke","version":"1.0.0","private":true}\n',
);
const env = {
  ...process.env,
  XDG_DATA_HOME: path.join(scratch, "data"),
  XDG_CONFIG_HOME: path.join(scratch, "config"),
  XDG_CACHE_HOME: path.join(scratch, "cache"),
  LIBGL_ALWAYS_SOFTWARE: "1",
  WEBKIT_DISABLE_DMABUF_RENDERER: "1",
  SITECMD_DEV_PLAINTEXT_SECRETS: "1",
};
const log = createWriteStream(path.join(scratch, "desktop.log"));
const evidence = { checks: [], scratch };
const passed = (check) => {
  evidence.checks.push(check);
  console.log(`PASS ${check}`);
};
let desktop;
let mcp;
try {
  desktop = await startNativeDesktop({ binary, env, log });
  passed("native startup and IPC");
  for (const command of ["delete_project", "run_project_command", "run_scan_execution"]) {
    await assert.rejects(
      desktop.invoke(command, { projectId: -1 }),
      /not found|not allowed|denied/i,
    );
  }
  passed("main webview denies privileged commands");
  const url = "http://localhost:4173";
  const projectId = await desktop.invoke("add_project", {
    name: "Native smoke",
    path: path.dirname(source),
    framework: null,
    urls: [{ url, environment: "local", source: "manual" }],
  });
  const database = path.join(env.XDG_DATA_HOME, "com.sitecmd.app/sitecmd.db");
  const connect = async () => {
    const client = new Client({ name: "codex", version: "native-smoke" });
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [bundle],
      env: { ...env, SITECMD_DB_PATH: database },
      stderr: "pipe",
    });
    transport.stderr?.on("data", (data) => log.write(data));
    try {
      await client.connect(transport);
      return client;
    } catch (error) {
      await transport.close();
      throw error;
    }
  };
  mcp = await connect();
  const call = async (name, args) => {
    const result = await mcp.callTool({ name, arguments: args }, undefined, { timeout: 120000 });
    if (result.isError) throw new Error(`${name}: ${JSON.stringify(result)}`);
    return (
      result.content
        ?.filter((part) => part.type === "text")
        .map((part) => part.text)
        .join("\n") ?? ""
    );
  };
  await call("run_scan", { project_id: projectId, url, scope: "code", wait: true });
  const checkId = "code_scan.tls-verification-disabled";
  assert.match(await call("get_issues", { url }), /tls-verification-disabled/);
  passed("MCP queues a real Code Scan and reads its findings");
  const issueArgs = { projectId, envUrl: url, checkId };
  await desktop.invoke("ignore_issue", issueArgs);
  await mcp.close();
  mcp = undefined;
  await desktop.close();
  desktop = undefined;
  desktop = await startNativeDesktop({ binary, env, log });
  assert.equal((await desktop.invoke("get_issue_state", issueArgs))[0], "ignored");
  assert.ok((await desktop.invoke("get_projects")).some((project) => project.id === projectId));
  passed("project and issue state survive a native restart");
  await desktop.invoke("reopen_issue", issueArgs);
  mcp = await connect();
  const attempt = await call("start_fix", {
    project_id: projectId,
    url,
    check_id: checkId,
    wait: true,
  });
  const attemptId = Number(/Fix attempt #(\d+) is briefed/.exec(attempt)?.[1]);
  assert.ok(attemptId, attempt);
  await call("get_fix_brief", { attempt_id: attemptId });
  await writeFile(
    path.join(source, "index.js"),
    'console.log("TLS verification uses the secure default");\n',
  );
  await call("request_verification", {
    attempt_id: attemptId,
    summary: "Removed the TLS verification override from the smoke fixture.",
  });
  let status = "";
  for (let attempt = 0; attempt < 60; attempt++) {
    status = await call("get_fix_status", { attempt_id: attemptId });
    if (/^Status: verified$/m.test(status)) break;
    await delay(1000);
  }
  assert.match(status, /^Status: verified$/m);
  passed("MCP fix verification rescans the changed source");
  evidence.result = "passed";
} catch (error) {
  evidence.result = "failed";
  throw error;
} finally {
  try {
    await mcp?.close();
  } finally {
    try {
      await desktop?.close();
    } finally {
      log.end();
      await writeFile(path.join(scratch, "result.json"), JSON.stringify(evidence, null, 2) + "\n");
      console.log(`Native smoke evidence: ${scratch}`);
    }
  }
}
