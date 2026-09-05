import { spawn } from "node:child_process";
import { once } from "node:events";
import { createServer } from "node:net";
import { setTimeout as delay } from "node:timers/promises";

async function availablePort() {
  const server = createServer();
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const { port } = server.address();
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  return port;
}

export async function webdriverRequest(base, route, body, method = "POST") {
  const response = await fetch(`${base}${route}`, {
    method,
    headers: { "Content-Type": "application/json" },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: AbortSignal.timeout(120000),
  });
  const result = await response.json();
  if (!response.ok || result.value?.error) {
    throw new Error(`Desktop WebDriver: ${JSON.stringify(result.value)}`);
  }
  return result.value;
}

export async function startNativeDesktop({ binary, env, log }) {
  const port = await availablePort();
  let nativePort = await availablePort();
  while (nativePort === port) nativePort = await availablePort();
  const driver = spawn(
    "tauri-driver",
    ["--port", String(port), "--native-port", String(nativePort)],
    {
      env,
      detached: true,
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let launchError;
  driver.on("error", (error) => {
    launchError = error;
  });
  driver.stdout.on("data", (data) => log.write(data));
  driver.stderr.on("data", (data) => log.write(data));
  const base = `http://127.0.0.1:${port}`;
  const request = (route, body, method) => webdriverRequest(base, route, body, method);
  const close = async () => {
    if (!driver.pid) return;
    // Closing a SiteCMD window hides it, so stop the owned process group to test a real restart.
    const stop = (signal) => {
      try {
        process.kill(-driver.pid, signal);
      } catch (error) {
        if (error.code !== "ESRCH") throw error;
      }
    };
    stop("SIGTERM");
    await delay(500);
    stop("SIGKILL");
  };
  try {
    let ready = false;
    for (let attempt = 0; attempt < 60; attempt++) {
      if (launchError) throw launchError;
      if (driver.exitCode !== null) throw new Error(`tauri-driver exited: ${driver.exitCode}`);
      try {
        await request("/status", undefined, "GET");
        ready = true;
        break;
      } catch {
        await delay(500);
      }
    }
    if (!ready) throw new Error("Desktop driver did not start");
    const { sessionId } = await request("/session", {
      capabilities: { alwaysMatch: { "tauri:options": { application: binary } } },
    });
    await request(`/session/${sessionId}/timeouts`, { script: 120000 });
    const invoke = async (command, args = {}) => {
      const result = await request(`/session/${sessionId}/execute/async`, {
        script:
          "const [command, args, done] = arguments; window.__TAURI_INTERNALS__.invoke(command, args).then(value => done({value}), error => done({error: String(error)}));",
        args: [command, args],
      });
      if (result.error) throw new Error(`${command}: ${result.error}`);
      return result.value;
    };
    if ((await invoke("ping")) !== "pong") throw new Error("Desktop health check failed");
    return { invoke, close };
  } catch (error) {
    await close();
    throw error;
  }
}
