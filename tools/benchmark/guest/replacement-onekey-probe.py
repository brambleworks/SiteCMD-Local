import ctypes
import json
import os
import pathlib
import secrets
import select
import signal
import subprocess
import tempfile
import time

from onekey_fixtures import Fixtures

assert os.getuid() == 0, "The judge must remain separate from candidate UID 65534"
assert ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) == 0
checks, exchanges = [], []


def check(name, passed, detail=None):
    checks.append({"name": name, "passed": bool(passed), "detail": detail})


class Candidate:
    def __init__(self, ca):
        self.reader, writer = os.pipe()
        self.buffer = b""
        self.logs = tempfile.TemporaryFile()
        environment = {"PATH": "/usr/bin:/bin", "PYTHONDONTWRITEBYTECODE": "1", "SSL_CERT_FILE": str(ca)}
        self.process = subprocess.Popen(
            ["/usr/bin/prlimit", "--fsize=1048576:1048576", "--nofile=128:128", "--",
             "/runtime/bin/python", "-B", "/candidate.py", str(writer)],
            stdin=subprocess.PIPE, stdout=self.logs, stderr=self.logs, pass_fds=(writer,),
            user=65534, group=65534, extra_groups=[], env=environment, start_new_session=True,
        )
        os.close(writer)
        status = pathlib.Path(f"/proc/{self.process.pid}/status").read_text()
        fields = dict(line.split(":", 1) for line in status.splitlines() if ":" in line)
        assert fields["Uid"].split() == ["65534"] * 4
        assert int(fields["CapEff"].strip(), 16) == 0

    def receive(self, timeout=8):
        deadline = time.monotonic() + timeout
        while b"\n" not in self.buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([self.reader], [], [], remaining)[0]:
                raise ValueError("Candidate response timed out")
            chunk = os.read(self.reader, 4096)
            if not chunk:
                raise ValueError("Candidate result channel closed")
            self.buffer += chunk
            if len(self.buffer) > 65536:
                raise ValueError("Candidate result exceeded the protocol bound")
        line, self.buffer = self.buffer.split(b"\n", 1)
        reply = json.loads(line)
        if not isinstance(reply, dict) or "passed" in reply or "checks" in reply:
            raise ValueError("Candidate cannot supply a verdict")
        return reply

    def call(self, operation, timeout=8, **arguments):
        identity = secrets.token_hex(16)
        job = {"id": identity, "operation": operation, **arguments}
        self.process.stdin.write((json.dumps(job) + "\n").encode())
        self.process.stdin.flush()
        reply = self.receive(timeout)
        if reply.get("id") != identity:
            raise ValueError("Candidate reply does not match the command")
        exchanges.append({"operation": operation, "reply": reply})
        return reply

    def close(self):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
        self.process.wait(timeout=3)
        self.process.stdin.close()
        os.close(self.reader)
        self.logs.seek(0)
        content = self.logs.read(8192).decode(errors="replace")
        self.logs.close()
        return content


def exercise(candidate, fixtures):
    lifecycle_errors = []

    def lifecycle(operation):
        reply = candidate.call(operation)
        required = "ready" if operation == "new" else "closed"
        if reply.get(required) is not True or reply.get("errorType") or reply.get("error"):
            lifecycle_errors.append({"operation": operation, "reply": reply})
        return reply

    def request(method, server, path, headers=None, data=None, timeout=8):
        args = {"url": fixtures.urls[server] + path, "headers": headers}
        if method == "post":
            args["data"] = data
        reply = candidate.call(method, timeout=timeout, **args)
        return reply, reply.get("response")

    def response_ok(response, server, path, status=200):
        return isinstance(response, dict) and response.get("status") == status and response.get("body") == fixtures.expected(server, path)

    def closed_transport(label):
        fixture_server = fixtures.servers["trusted"]
        prior_requests = len(fixture_server.requests)
        get_reply, _ = request("get", "trusted", "/closed-get-" + secrets.token_hex(8))
        post_reply, _ = request("post", "trusted", "/closed-post-" + secrets.token_hex(8), data={"key": token})
        requests_added = len(fixture_server.requests) - prior_requests
        check(
            label,
            get_reply.get("errorType") == "RuntimeError"
            and post_reply.get("errorType") == "RuntimeError"
            and requests_added == 0,
            {"get": get_reply, "post": post_reply, "requestsAdded": requests_added},
        )

    assert candidate.receive() == {"ready": True}, "Candidate package did not import"
    lifecycle("new")
    check("context manager preserves client identity", candidate.call("enter").get("sameClient") is True)
    token = secrets.token_hex(16)
    for method, server in (("get", "trusted"), ("get", "plain"), ("post", "trusted"), ("post", "plain")):
        path = "/binary-" + secrets.token_hex(8) + "?q=hello%20world"
        payload = {"key": token, "appId": 123}
        reply, response = request(method, server, path, {"X-Benchmark": token}, payload)
        observed = fixtures.servers[server].requests
        reached = any(row == {"method": method.upper(), "path": path, "echo": token, "data": payload if method == "post" else None} for row in observed)
        check(f"{server} {method} preserves request and binary response", reached and response_ok(response, server, path), reply.get("error"))
        check(f"{server} {method} preserves timeout contract", isinstance(response, dict) and response.get("timeout") == dict.fromkeys(("connect", "read", "write", "pool"), 60.0))
    path = "/status-" + secrets.token_hex(8)
    reply, response = request("get", "trusted", path)
    check("HTTP error status remains a response", response_ok(response, "trusted", path, 418), reply.get("error"))
    paths = ["/concurrent-" + secrets.token_hex(8) for _ in range(3)]
    reply = candidate.call("concurrent", urls=[fixtures.urls["trusted"] + path for path in paths])
    responses = reply.get("responses", [])
    check("concurrent requests preserve binary responses", len(responses) == len(paths) and all(response_ok(response, "trusted", path) for response, path in zip(responses, paths)))
    path = "/delayed-" + secrets.token_hex(8)
    reply, response = request("get", "trusted", path)
    check("ordinary delayed responses remain usable", response_ok(response, "trusted", path), reply.get("error"))
    lifecycle("exit")
    closed_transport("context manager closes the production transport")
    reply = candidate.call("exceptional-context")
    check("context manager propagates body exceptions", reply.get("propagated") is True, reply)
    closed_transport("exceptional context closes the production transport")
    lifecycle("new")
    lifecycle("close")
    lifecycle("close")
    closed_transport("explicit close is idempotent and closes the production transport")

    lifecycle("new")
    for server in ("untrusted", "wrong-host", "expired"):
        for attempt, method in enumerate(("get", "get", "post", "post"), 1):
            fixture_server = fixtures.servers[server]
            prior_requests, prior_rejections = len(fixture_server.requests), len(fixture_server.rejections)
            reply, _ = request(method, server, "/certificate-" + secrets.token_hex(8), data={"key": token})
            rejection_deadline = time.monotonic() + 1
            while len(fixture_server.rejections) == prior_rejections and time.monotonic() < rejection_deadline:
                time.sleep(0.01)
            rejection = len(fixture_server.rejections) > prior_rejections
            check(f"{server} {method} attempt {attempt} rejects the certificate", reply.get("errorType") == "ConnectError" and "CERTIFICATE_VERIFY_FAILED" in reply.get("error", "") and len(fixture_server.requests) == prior_requests and rejection, reply.get("error"))
    lifecycle("close")

    if pathlib.Path("/slow-check").exists():
        for method in ("get", "post"):
            lifecycle("new")
            started = time.monotonic()
            reply, _ = request(method, "trusted", "/stall-" + secrets.token_hex(8), data={"key": token}, timeout=69)
            elapsed = time.monotonic() - started
            check(f"{method} actual 60 second read deadline", reply.get("errorType") == "ReadTimeout" and 59 <= elapsed <= 64, {"elapsed": elapsed, "error": reply.get("error")})
            lifecycle("close")

    check("lifecycle operations complete without errors", not lifecycle_errors, lifecycle_errors or None)


logs = ""
candidate = None
setup_error = None
try:
    with Fixtures() as fixtures:
        candidate = Candidate(fixtures.public_ca)
        try:
            exercise(candidate, fixtures)
        except Exception as error:
            check("candidate execution contract", False, f"{type(error).__name__}: {error}")
        finally:
            logs = candidate.close()
        observed = {name: {"requests": server.requests, "tlsRejections": server.rejections} for name, server in fixtures.servers.items()}
except Exception as error:
    setup_error = f"{type(error).__name__}: {error}"
    observed = {}
result = {
    "passed": setup_error is None and len(checks) in (29, 31) and all(row["passed"] for row in checks),
    "checks": checks, "setupError": setup_error, "candidateLogs": logs, "exchanges": exchanges, "serverObservations": observed,
    "judgeIsolation": {"judgeUid": os.getuid(), "candidateUid": 65534, "candidateSuppliesVerdict": False},
}
print(json.dumps(result))
