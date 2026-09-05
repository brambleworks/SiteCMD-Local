import { createServer } from "node:http";
import { once } from "node:events";
import { afterEach, expect, it } from "vitest";
import { webdriverRequest } from "./lib/native-webdriver.mjs";

let server;
afterEach(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
});
async function endpoint(status, payload) {
  server = createServer((_request, response) => {
    response.writeHead(status, { "Content-Type": "application/json" });
    response.end(JSON.stringify(payload));
  }).listen(0, "127.0.0.1");
  await once(server, "listening");
  return `http://127.0.0.1:${server.address().port}`;
}

it("unwraps a successful native protocol response", async () => {
  const base = await endpoint(200, { value: { sessionId: "native-session" } });
  await expect(webdriverRequest(base, "/session", {})).resolves.toEqual({
    sessionId: "native-session",
  });
});
it("rejects a W3C error even with a successful HTTP status", async () => {
  const base = await endpoint(200, {
    value: { error: "invalid session id", message: "app exited" },
  });
  await expect(webdriverRequest(base, "/session", {})).rejects.toThrow("invalid session id");
});
it("rejects an HTTP failure even without a W3C error field", async () => {
  const base = await endpoint(500, { value: "driver failed" });
  await expect(webdriverRequest(base, "/session", {})).rejects.toThrow("driver failed");
});
