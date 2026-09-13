import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const directory = path.dirname(fileURLToPath(import.meta.url));

function check(name, actual) {
  return { name, actual: actual === true, pass: actual === true };
}

export function gradeRedirectCandidate(files) {
  const source = files["grappelli/views/switch.py"];
  const response = spawnSync(
    "/usr/bin/python3",
    [path.join(directory, "replacement-redirect-python.py")],
    {
      input: JSON.stringify({ source }),
      encoding: "utf8",
      timeout: 10000,
      maxBuffer: 1024 * 1024,
    },
  );
  let observed = {};
  let probeError = null;
  try {
    if (response.status !== 0)
      throw new Error(response.stderr || `Python probe exited ${response.status}`);
    const parsed = JSON.parse(response.stdout.trim().split("\n").at(-1));
    if (parsed.error) throw new Error(parsed.error);
    observed = parsed.observed;
  } catch (error) {
    probeError = `${error.name}: ${error.message}`;
  }
  const acceptance = [
    ["Host-confusion redirects are rejected", "hostileHostRejected"],
    ["Protocol-relative redirects are rejected", "protocolRelativeRejected"],
    ["Userinfo host-confusion redirects are rejected", "userinfoRejected"],
    ["Unexpected destination ports are rejected", "wrongPortRejected"],
    ["Backslash host-confusion redirects are rejected", "backslashRejected"],
    ["Control-character redirects are rejected", "controlCharacterRejected"],
    ["Dangerous URL schemes are rejected", "dangerousSchemeRejected"],
    ["HTTPS downgrade redirects are rejected", "httpsDowngradeRejected"],
    ["Missing redirect targets are rejected", "missingRedirectRejected"],
  ].map(([name, key]) => check(name, observed[key]));
  const regressions = [
    ["Relative redirects remain available", "relativeRedirectPreserved"],
    ["Login and session state remain intact", "loginAndSessionPreserved"],
    ["Permission failures still return safely", "permissionFailurePreserved"],
  ].map(([name, key]) => check(name, observed[key]));
  return {
    observed,
    acceptance,
    regressions,
    acceptancePass: acceptance.every((item) => item.pass),
    regressionsPass: regressions.every((item) => item.pass),
    ...(probeError ? { probeError } : {}),
  };
}
